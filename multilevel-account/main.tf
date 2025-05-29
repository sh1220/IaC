terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0" # optional
    }
  }
}


# Configure the AWS Provider
provider "aws" {
  region                   = "ap-northeast-2"
  profile                  = "terraform-admin"
  shared_credentials_files = ["${path.module}/.aws/credentials"]
}

# GitHub Actions에서 AWS에 접근할 수 있도록 OIDC 공급자 설정
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]
  # GitHub OIDC의 고정된 Thumbprint
  # thumbprint_list는 GitHub의 OIDC 인증 서버의 신뢰성을 검증하기 위한 SHA-1 인증서 지문(Thumbprint)
}

# GitHub Actions에서 사용할 IAM Role 정의
# 이 Role은 특정 GitHub 저장소에서 OIDC 토큰으로만 사용할 수 있도록 제한됨
resource "aws_iam_role" "github_oidc_role" {
  name = "github-actions-deploy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
          StringEquals = {
            # GitHub OIDC 토큰의 대상(Audience)이 sts.amazonaws.com인 경우만 허용
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            # GitHub sh1220에서 발생한 워크플로만 허용 (브랜치, 워크플로 경로 등 추가로 제한 가능)
            "token.actions.githubusercontent.com:sub" = "repo:sh1220/*"
          }
        }
      }
    ]
  })
}

# 위 Role에 필요한 권한을 부여 (기본은 AdministratorAccess이지만 상황에 맞게 조정 가능)
resource "aws_iam_role_policy_attachment" "github_oidc_policy_attach" {
  role       = aws_iam_role.github_oidc_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "github_actions_role_arn" {
  description = "ARN of the GitHub Actions IAM Role"
  value       = aws_iam_role.github_oidc_role.arn
}

# 새로운 organization 생성
resource "aws_organizations_organization" "org" {
  aws_service_access_principals = [ #조직 전체 수준에서 접근을 허용하고, Delegated Administrator(위임 관리자)로 계정에 등록할 수 있게 해줌.
    "cloudtrail.amazonaws.com",     # AWS CloudTrail이 전체 조직의 로그를 수집할 수 있게 함
    "config.amazonaws.com",         # AWS Config가 전체 조직의 리소스를 추적·관리할 수 있게 함
    "guardduty.amazonaws.com",      # guardduty / 위협탐지
    "securityhub.amazonaws.com",    #security hub / 조직 보안 표준
    "inspector2.amazonaws.com",
    "detective.amazonaws.com",
    "sso.amazonaws.com"
  ]

  feature_set          = "ALL"                      # 모든 기능 사용 가능 (OU, SCP, consolidated billing 등)
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"] # 실제로 어떤 정책(SCP, TAG_POLICY 등)을 켤지 지정
  # SERVICE_CONTROL_POLICY : SCP
}


# OUs 설정
resource "aws_organizations_organizational_unit" "infrastructure_ou" {
  name      = "infra_OU"
  parent_id = aws_organizations_organization.org.roots[0].id
}


resource "aws_organizations_organizational_unit" "security_ou" {
  name      = "security_OU"
  parent_id = aws_organizations_organization.org.roots[0].id
}


resource "aws_organizations_organizational_unit" "workload_ou" {
  name      = "workload_OU"
  parent_id = aws_organizations_organization.org.roots[0].id
}

resource "aws_organizations_organizational_unit" "prod_ou" {
  name      = "prod_OU"
  parent_id = aws_organizations_organizational_unit.workload_ou.id # workload 아래에 존재
}


# account 설정
resource "aws_organizations_account" "network_account" {
  name      = "network-team-account"
  email     = "network-team@cloudfence.com" # 반드시 고유해야 함
  parent_id = aws_organizations_organizational_unit.infrastructure_ou.id
}

resource "aws_organizations_account" "identity_account" {
  name      = "identity-team-account"
  email     = "identity-team@cloudfence.com" # 반드시 고유해야 함
  parent_id = aws_organizations_organizational_unit.infrastructure_ou.id
}


resource "aws_organizations_account" "log_account" {
  name      = "log-team-account"
  email     = "log-team@cloudfence.com" # 반드시 고유해야 함
  parent_id = aws_organizations_organizational_unit.security_ou.id
}

resource "aws_organizations_account" "security_account" {
  name      = "security-team-account"
  email     = "security-team@cloudfence.com" # 반드시 고유해야 함
  parent_id = aws_organizations_organizational_unit.security_ou.id
}


resource "aws_organizations_account" "workload_account_A" {
  name      = "workload-team-account-A"
  email     = "workload-team-A@cloudfence.com" # 반드시 고유해야 함
  parent_id = aws_organizations_organizational_unit.prod_ou.id
}


# Delegated Administrator 등록
resource "aws_organizations_delegated_administrator" "sso_delegate" {
  account_id        = aws_organizations_account.identity_account.id
  service_principal = "sso.amazonaws.com"
}

# 현재 활성화된 IAM Identity Center 인스턴스에 연결된 디렉터리 정보를 불러오기
# 사용자(user), 그룹(group) 등을 생성할 때 필수적으로 사용됨.
# 일반적으로 하나의 디렉터리만 존재하기 때문에 파라미터 없이 조회 가능
# IAM Identity Center의 인스턴스 정보 조회
data "aws_ssoadmin_instances" "this" {}

# 인스턴스 만들기
resource "aws_identitystore_user" "example" {
  identity_store_id = data.aws_ssoadmin_instances.this.identity_store_ids[0]
  user_name         = "admin"
  display_name      = "Admin User"
  emails {
    value   = "gibefef126@daxiake.com"
    primary = true
  }
  name {
    given_name  = "John"
    family_name = "Doe"
  }
}


# AdministratorAccess라는 이름의 Permission Set(권한 세트)을 생성.
# Permission Set은 일종의 SSO 역할(Role) 이며, IAM Policy의 집합.
# 여기선 8시간 세션을 지정 (PT8H → ISO 8601 포맷).
# 이 Permission Set에는 별도로 정책을 추가할 수 있음. (inline_policy, managed_policies 등).
resource "aws_ssoadmin_permission_set" "admin_pset" {
  name             = "AdministratorAccess"
  description      = "Full admin access"
  instance_arn     = data.aws_ssoadmin_instances.this.arns[0]
  session_duration = "PT8H"
}


# admin의 권한 설정
resource "aws_ssoadmin_managed_policy_attachment" "admin_attach" {
  instance_arn       = data.aws_ssoadmin_instances.this.arns[0]
  permission_set_arn = aws_ssoadmin_permission_set.admin_pset.arn
  managed_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}


# 앞서 생성한 SSO 사용자(admin@example.com)에게 앞서 생성한 Permission Set(AdministratorAccess)을 
# 특정 AWS 계정 (identity_account)에 할당.
# principal_id: 사용자 또는 그룹 ID (여기서는 사용자)
# principal_type: "USER" 또는 "GROUP" 지정
# target_id: 조직 내 계정의 ID
# target_type: 고정값 "AWS_ACCOUNT"
resource "aws_ssoadmin_account_assignment" "admin_assignment" {
  instance_arn       = data.aws_ssoadmin_instances.this.arns[0]
  permission_set_arn = aws_ssoadmin_permission_set.admin_pset.arn
  principal_id       = aws_identitystore_user.example.user_id
  principal_type     = "USER"
  target_id          = aws_organizations_account.identity_account.id
  target_type        = "AWS_ACCOUNT"
}

locals {
  target_accounts = [
    aws_organizations_account.identity_account.id,
    aws_organizations_account.network_account.id,
    aws_organizations_account.log_account.id,
    aws_organizations_account.security_account.id,
    aws_organizations_account.workload_account_A.id
  ]
}

# aws_ssoadmin_* 계열 리소스를 사용하는데, 이건 기본적으로 다음 조건이 필요:
# SSO 인스턴스가 미리 수동으로 활성화되어 있어야 함
# 루트 계정으로도 일부 API 호출은 거부될 수 있음 (특히 IAM Identity Center/SSO 관련)
# 권한 및 신뢰 정책 구성까지 필요한 경우가 있음
resource "aws_ssoadmin_account_assignment" "admin_assignment_all" {
  for_each = toset(local.target_accounts)

  instance_arn       = data.aws_ssoadmin_instances.this.arns[0]
  permission_set_arn = aws_ssoadmin_permission_set.admin_pset.arn
  principal_id       = aws_identitystore_user.example.user_id
  principal_type     = "USER"
  target_id          = each.key
  target_type        = "AWS_ACCOUNT"
}


# Delegate GuardDuty, SecurityHub, Inspector, Detective
resource "aws_organizations_delegated_administrator" "guardduty_delegate" {
  account_id        = aws_organizations_account.security_account.id
  service_principal = "guardduty.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "securityhub_delegate" {
  account_id        = aws_organizations_account.security_account.id
  service_principal = "securityhub.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "inspector_delegate" {
  account_id        = aws_organizations_account.security_account.id
  service_principal = "inspector2.amazonaws.com"
}

resource "aws_organizations_delegated_administrator" "detective_delegate" {
  account_id        = aws_organizations_account.security_account.id
  service_principal = "detective.amazonaws.com"
}



# CloudTrail과 CloudWatch logs들에 대한 삭제 deny
resource "aws_organizations_policy" "deny_delete_logs" {
  name        = "DenyDeleteCloudTrail"
  description = "Prevent deletion of CloudTrail logs"
  content = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Deny",
        "Action" : [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "logs:DeleteLogGroup",
          "logs:DeleteLogStream"
        ],
        "Resource" : "*"
      }
    ]
  })
  type = "SERVICE_CONTROL_POLICY"
}
# log account에 적용
resource "aws_organizations_policy_attachment" "attach_to_log_account" {
  policy_id = aws_organizations_policy.deny_delete_logs.id
  target_id = aws_organizations_account.log_account.id
}

# SCP는 일단 하지말기 
# governance를 잡는거라서 다 해보고 넣는것도 좋다.
# 처으부터 글허게 할필요 ㅇ벗다
# Idneity Center를 통해서만 유저를 만들기(IAM USer를 만들지 말자. / IAM create user)

# Security OU 소속 모든 계정에서 S3 버킷과 객체에 public-read ACL을 설정하지 못하게 강제로 차단
resource "aws_organizations_policy" "deny_s3_public" {
  name        = "DenyS3PublicAccess"
  description = "Deny public access to all S3 buckets"
  content = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Deny",
        Action = [
          "s3:PutBucketAcl",
          "s3:PutObjectAcl"
        ],
        Resource = "*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "public-read"
          }
        }
      }
    ]
  })
  type = "SERVICE_CONTROL_POLICY"
}

resource "aws_organizations_policy_attachment" "attach_scp_to_ou" {
  policy_id = aws_organizations_policy.deny_s3_public.id
  target_id = aws_organizations_organizational_unit.security_ou.id
}


## sso 포탈 url 출력
output "sso_portal_url" {
  value       = "https://${data.aws_ssoadmin_instances.this.identity_store_ids[0]}.awsapps.com/start"
  description = "SSO 사용자 포털 URL"
}



# aws organizations enable-aws-service-access --service-principal sso.amazonaws.com
# organization에서 sso 허용

# policy 활성화 organization => 정책 => 활성화

