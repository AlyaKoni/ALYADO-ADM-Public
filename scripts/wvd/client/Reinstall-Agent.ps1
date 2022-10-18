$Token = "PleaseSpecify"
cd C:\DeployAgent
.\DeployAgent.ps1 -AgentInstallerFolder .\RDInfraAgentInstall -AgentBootServiceInstallerFolder .\RDAgentBootLoaderInstall -RegistrationToken $Token
