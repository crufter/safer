package safer

func inspectDirectTool(tool string, args []string, workDir, source string) []Finding {
	if source == "" {
		source = "command"
	}

	var findings []Finding
	switch tool {
	case "kubectl", "k":
		findings = append(findings, inspectKubectl(args, source)...)
	case "helm":
		findings = append(findings, inspectHelm(args, source)...)
	case "docker":
		findings = append(findings, inspectDocker(args, source)...)
	case "docker-compose":
		findings = append(findings, inspectDockerCompose(args, source)...)
	case "git":
		findings = append(findings, inspectGit(args, source)...)
	case "terraform", "tofu":
		findings = append(findings, inspectTerraform(tool, args, source)...)
	case "pulumi":
		findings = append(findings, inspectPulumi(args, source)...)
	case "npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "go", "apt", "apt-get", "dnf", "yum", "brew":
		findings = append(findings, inspectPackageManager(tool, args, source)...)
	case "systemctl", "service":
		findings = append(findings, inspectServiceManager(tool, args, source)...)
	case "aws", "gcloud", "az":
		findings = append(findings, inspectCloudCLI(tool, args, source)...)
	case "gh":
		findings = append(findings, inspectGitHubCLI(args, source)...)
	default:
		findings = append(findings, inspectSimpleCommand(tool, args, source)...)
	}

	findings = append(findings, inspectShellPatterns(displayCommand(append([]string{tool}, args...)), source)...)
	return uniqueFindings(findings)
}
