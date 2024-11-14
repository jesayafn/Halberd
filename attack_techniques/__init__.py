# AWS Techniques
from .aws.aws_establish_access import AWSEstablishAccess
from .aws.aws_enumerate_s3_buckets import AWSEnumerateS3Buckets
from .aws.aws_enumerate_iam_users import AWSEnumerateIAMUsers
from .aws.aws_enumerate_iam_roles import AWSEnumerateIAMRoles
from .aws.aws_enumerate_iam_policies import AWSEnumerateIAMPolicies
from .aws.aws_enumerate_dynamodb_tables import AWSEnumerateDynamoDBTables
from .aws.aws_enumerate_s3_bucket_objects import AWSEnumerateS3BucketObjects
from .aws.aws_enumerate_ec2_instances import AWSEnumerateEC2Instances
from .aws.aws_enumerate_cloudtrail_trails import AWSEnumerateCloudtrailTrails
from .aws.aws_enumerate_guardduty_detectors import AWSEnumerateGuarddutyDetectors
from .aws.aws_recon_iam_user_info import AWSReconIAMUserInfo
from .aws.aws_recon_account_authorization_info import AWSReconAccountAuthorizationInfo
from .aws.aws_recon_risky_iam_policy_users import AWSReconRiskyIAMPolicyUsers
from .aws.aws_recon_s3_public_buckets import AWSReconS3PublicBuckets
from .aws.aws_recon_ec2_over_permissive_sg import AWSReconEC2OverPermissiveSG
from .aws.aws_get_bucket_acl import AWSGetS3BucketACL
from .aws.aws_assume_iam_role import AWSAssumeIAMRole
from .aws.aws_exfil_s3_bucket import AWSExfilS3Bucket
from .aws.aws_delete_s3_bucket import AWSDeleteS3Bucket
from .aws.aws_delete_dynamodb_table import AWSDeleteDynamoDBTable
from .aws.aws_delete_s3_bucket_object import AWSDeleteS3BucketObject
from .aws.aws_disable_cloudtrail_logging import AWSDisableCloudtrailLogging
from .aws.aws_modify_guardduty_trusted_ip import AWSModifyGuaddutyTrustedIP
from .aws.aws_expose_s3_bucket_public import AWSExposeS3BucketPublic

# Azure Techniques
from .azure.azure_password_spray import AzurePasswordSpray
from .azure.azure_establish_access_as_user import AzureEstablishAccessAsUser
from .azure.azure_establish_access_as_app import AzureEstablishAccessAsApp
from .azure.azure_enumerate_vm import AzureEnumerateVm
from .azure.azure_enumerate_resources import AzureEnumerateResources
from .azure.azure_enumerate_resource_groups import AzureEnumerateResourceGroups
from .azure.azure_enumerate_assigned_roles import AzureEnumerateRoleAssignment
from .azure.azure_enumerate_vmss import AzureEnumerateVMSS
from .azure.azure_enumerate_vm_in_vmss import AzureEnumerateVMInVMSS
from .azure.azure_assign_role import AzureAssignRole
from .azure.azure_create_new_resource_group import AzureCreateNewResourceGroup
from .azure.azure_dump_automation_accounts import AzureDumpAutomationAccounts
from .azure.azure_dump_keyvault import AzureDumpKeyVault
from .azure.azure_dump_storage_account import AzureDumpStorageAccount
from .azure.azure_elevate_access_from_entra_id import AzureElevateAccessFromEntraId
from .azure.azure_expose_storage_account import AzureExposeStorageAccountPublic
from .azure.azure_modify_keyvault_access import AzureModifyKeyVaultAccess
from .azure.azure_delete_vm import AzureDeleteVm
from .azure.azure_share_storage_account_container import AzureShareStorageAccountContainer
from .azure.azure_share_vm_disk import AzureShareVmDisk
from .azure.azure_abuse_azure_policy_to_disable_logging import AzureAbuseAzurePolicyToDisableLogging
from .azure.azure_deploy_malicious_extension_on_vm import AzureDeployMaliciousExtensionOnVM
from .azure.azure_execute_script_on_vm import AzureExecuteScriptOnVM
from .azure.azure_remove_role_asignment import AzureRemoveRoleAssignment

# Entra ID Techniques
from .entra_id.entra_recon_tenant_info import EntraReconTenantInfo
from .entra_id.entra_device_code_flow_auth import EntraDeviceCodeFlowAuth
from .entra_id.entra_establish_access_as_user import EntraEstablishAccessAsUser
from .entra_id.entra_establish_access_as_app import EntraEstablishAccessAsApp
from .entra_id.entra_establish_access_with_token import EntraEstablishAccessWithToken
from .entra_id.entra_bruteforce_graph_apps import EntraBruteforceGraphApps
from .entra_id.entra_password_spray import EntraPasswordSpray
from .entra_id.entra_bruteforce_password import EntraBruteforcePassword
from .entra_id.entra_check_user_validity import EntraCheckUserValidity
from .entra_id.entra_enumerate_users import EntraEnumerateUsers
from .entra_id.entra_enumerate_apps import EntraEnumerateApps
from .entra_id.entra_enumerate_directory_roles import EntraEnumerateDirectoryRoles
from .entra_id.entra_enumerate_app_permissions import EntraEnumerateAppPermissions
from .entra_id.entra_enumerate_groups import EntraEnumerateGroups
from .entra_id.entra_enumerate_cap import EntraEnumerateCAP
from .entra_id.entra_enumerate_one_drive import EntraEnumerateOneDrive
from .entra_id.entra_enumerate_sp_site import EntraEnumerateSPSites
from .entra_id.entra_assign_directory_role import EntraAssignDirectoryRole
from .entra_id.entra_assign_app_permission import EntraAssignAppPermission
from .entra_id.entra_add_user_to_group import EntraAddUserToGroup
from .entra_id.entra_generate_app_credentials import EntraGenerateAppCredentials
from .entra_id.entra_create_backdoor_account import EntraCreateBackdoorAccount
from .entra_id.entra_invite_external_user import EntraInviteExternalUser
from .entra_id.entra_create_new_app import EntraCreateNewApp
from .entra_id.entra_add_trusted_ip_config import EntraAddTrustedIPConfig
from .entra_id.entra_remove_account_access import EntraRemoveAccountAccess

# M365 Techniques
from .m365.m365_deploy_email_deletion_rule import M365DeployEmailDelRule
from .m365.m365_deploy_mail_forwarding_rule import M365DeployEmailFrwdRule
from .m365.m365_exfil_user_mailbox import M365ExfilUserMailbox
from .m365.m365_search_outlook_messages import M365SearchOutlookMessages
from .m365.m365_search_teams_chat import M365SearchTeamsChat
from .m365.m365_search_teams_messages import M365SearchTeamsMessages
from .m365.m365_search_user_one_drive import M365SearchUserOneDrive
from .m365.m365_send_outlook_email import M365SendOutlookEmail

# GCP Techniques
from .gcp.gcp_establish_access_as_sa import GCPEstablishAccessAsServiceAccount