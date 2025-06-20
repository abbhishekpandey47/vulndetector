package db_langTypes

type (
	// TargetType represents the type of target
	TargetType string

	// OSType is an alias of TargetType for operating systems
	OSType = TargetType

	// LangType is an alias of TargetType for programming languages
	LangType = TargetType

	// ConfigType is an alias of TargetType for configuration files
	ConfigType = TargetType
)

// Config files
const (
	JSON                  ConfigType = "json"
	YAML                  ConfigType = "yaml"
	Dockerfile            ConfigType = "dockerfile"
	Terraform             ConfigType = "terraform"
	TerraformPlanJSON     ConfigType = "terraformplan"
	TerraformPlanSnapshot ConfigType = "terraformplan-snapshot"
	CloudFormation        ConfigType = "cloudformation"
	Kubernetes            ConfigType = "kubernetes"
	Helm                  ConfigType = "helm"
	Cloud                 ConfigType = "cloud"
	AzureARM              ConfigType = "azure-arm"
)

// Programming language dependencies
const (
	Bundler        LangType = "bundler"
	GemSpec        LangType = "gemspec"
	Cargo          LangType = "cargo"
	Composer       LangType = "composer"
	ComposerVendor LangType = "composer-vendor"
	Npm            LangType = "npm"
	NuGet          LangType = "nuget"
	DotNetCore     LangType = "dotnet-core"
	PackagesProps  LangType = "packages-props"
	Pip            LangType = "pip"
	Pipenv         LangType = "pipenv"
	Poetry         LangType = "poetry"
	Uv             LangType = "uv"
	CondaPkg       LangType = "conda-pkg"
	CondaEnv       LangType = "conda-environment"
	PythonPkg      LangType = "python-pkg"
	NodePkg        LangType = "node-pkg"
	Yarn           LangType = "yarn"
	Pnpm           LangType = "pnpm"
	Jar            LangType = "jar"
	Pom            LangType = "pom"
	Gradle         LangType = "gradle"
	Sbt            LangType = "sbt"
	GoBinary       LangType = "gobinary"
	GoModule       LangType = "gomod"
	JavaScript     LangType = "javascript"
	RustBinary     LangType = "rustbinary"
	Conan          LangType = "conan"
	Cocoapods      LangType = "cocoapods"
	Swift          LangType = "swift"
	Pub            LangType = "pub"
	Hex            LangType = "hex"
	Bitnami        LangType = "bitnami"
	Julia          LangType = "julia"

	K8sUpstream LangType = "kubernetes"
	EKS         LangType = "eks" // Amazon Elastic Kubernetes Service
	GKE         LangType = "gke" // Google Kubernetes Engine
	AKS         LangType = "aks" // Azure Kubernetes Service
	RKE         LangType = "rke" // Rancher Kubernetes Engine
	OCP         LangType = "ocp" // Red Hat OpenShift Container Platform
)

// Operating systems
const (
	Alma               OSType = "alma"
	Alpine             OSType = "alpine"
	Amazon             OSType = "amazon"
	Azure              OSType = "azurelinux"
	CBLMariner         OSType = "cbl-mariner"
	CentOS             OSType = "centos"
	Chainguard         OSType = "chainguard"
	Debian             OSType = "debian"
	Fedora             OSType = "fedora"
	OpenSUSE           OSType = "opensuse"
	OpenSUSELeap       OSType = "opensuse-leap"
	OpenSUSETumbleweed OSType = "opensuse-tumbleweed"
	Oracle             OSType = "oracle"
	Photon             OSType = "photon"
	RedHat             OSType = "redhat"
	Rocky              OSType = "rocky"
	SLEMicro           OSType = "slem"
	SLES               OSType = "sles"
	Ubuntu             OSType = "ubuntu"
	Wolfi              OSType = "wolfi"
)

// OSTypeAliases is a map of aliases for operating systems.
var OSTypeAliases = map[OSType]OSType{
	// This is used to map the old family names to the new ones for backward compatibility.
	"opensuse.leap":                OpenSUSELeap,
	"opensuse.tumbleweed":          OpenSUSETumbleweed,
	"suse linux enterprise micro":  SLEMicro,
	"suse linux enterprise server": SLES,
	// This is used to map OS names in EKS
	"amazon linux": Amazon,
	// This is used to map OS names in Kind
	"debian gnu/linux": Debian,
}
