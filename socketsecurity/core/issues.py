import json


__all__ = [
	"AllIssues",
	"badEncoding",
	"badSemver",
	"badSemverDependency",
	"bidi",
	"binScriptConfusion",
	"chronoAnomaly",
	"criticalCVE",
	"cve",
	"debugAccess",
	"deprecated",
	"deprecatedException",
	"explicitlyUnlicensedItem",
	"unidentifiedLicense",
	"noLicenseFound",
	"copyleftLicense",
	"nonpermissiveLicense",
	"miscLicenseIssues",
	"deprecatedLicense",
	"didYouMean",
	"dynamicRequire",
	"emptyPackage",
	"envVars",
	"extraneousDependency",
	"fileDependency",
	"filesystemAccess",
	"gitDependency",
	"gitHubDependency",
	"hasNativeCode",
	"highEntropyStrings",
	"homoglyphs",
	"httpDependency",
	"installScripts",
	"gptSecurity",
	"gptAnomaly",
	"gptMalware",
	"potentialVulnerability",
	"invalidPackageJSON",
	"invisibleChars",
	"licenseChange",
	"licenseException",
	"longStrings",
	"missingTarball",
	"majorRefactor",
	"malware",
	"manifestConfusion",
	"mediumCVE",
	"mildCVE",
	"minifiedFile",
	"missingAuthor",
	"missingDependency",
	"missingLicense",
	"mixedLicense",
	"ambiguousClassifier",
	"modifiedException",
	"modifiedLicense",
	"networkAccess",
	"newAuthor",
	"noAuthorData",
	"noBugTracker",
	"noREADME",
	"noRepository",
	"noTests",
	"noV1",
	"noWebsite",
	"nonFSFLicense",
	"nonOSILicense",
	"nonSPDXLicense",
	"notice",
	"obfuscatedFile",
	"obfuscatedRequire",
	"peerDependency",
	"semverAnomaly",
	"shellAccess",
	"shellScriptOverride",
	"suspiciousString",
	"telemetry",
	"trivialPackage",
	"troll",
	"typeModuleCompatibility",
	"uncaughtOptionalDependency",
	"unclearLicense",
	"shrinkwrap",
	"unmaintained",
	"unpublished",
	"unresolvedRequire",
	"unsafeCopyright",
	"unstableOwnership",
	"unusedDependency",
	"urlStrings",
	"usesEval",
	"zeroWidth",
	"floatingDependency",
	"unpopularPackage",
]
class badEncoding:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Source files are encoded using a non-standard text encoding."
		self.props = {"encoding": "Encoding"}
		self.suggestion = "Ensure all published files are encoded using a standard encoding such as UTF8, UTF16, UTF32, SHIFT-JIS, etc."
		self.title = "Bad text encoding"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is bad text encoding?"

	def __str__(self):
		return json.dumps(self.__dict__)


class badSemver:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package version is not a valid semantic version (semver)."
		self.suggestion = "All versions of all packages on npm should use use a valid semantic version. Publish a new version of the package with a valid semantic version. Semantic version ranges do not work with invalid semantic versions."
		self.title = "Bad semver"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is bad semver?"

	def __str__(self):
		return json.dumps(self.__dict__)


class badSemverDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package has dependencies with an invalid semantic version. This could be a sign of beta, low quality, or unmaintained dependencies."
		self.props = {"packageName": "Package name", "packageVersion": "Package version"}
		self.suggestion = "Switch to a version of the dependency with valid semver or override the dependency version if it is determined to be problematic."
		self.title = "Bad dependency semver"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is bad dependency semver?"

	def __str__(self):
		return json.dumps(self.__dict__)


class bidi:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Source files contain bidirectional unicode control characters. This could indicate a Trojan source supply chain attack. See: trojansource.codes for more information."
		self.suggestion = "Remove bidirectional unicode control characters, or clearly document what they are used for."
		self.title = "Bidirectional unicode control characters"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are bidirectional unicode control characters?"

	def __str__(self):
		return json.dumps(self.__dict__)


class binScriptConfusion:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package has multiple bin scripts with the same name.  This can cause non-deterministic behavior when installing or could be a sign of a supply chain attack"
		self.props = {"binScript": "Bin script"}
		self.suggestion = "Consider removing one of the conflicting packages.  Packages should only export bin scripts with their name"
		self.title = "Bin script confusion"
		self.emoji = "\ud83d\ude35\u200d\ud83d\udcab"
		self.nextStepTitle = "What is bin script confusion?"

	def __str__(self):
		return json.dumps(self.__dict__)


class chronoAnomaly:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Semantic versions published out of chronological order."
		self.props = {"prevChronoDate": "Previous chronological date", "prevChronoVersion": "Previous chronological version", "prevSemverDate": "Previous semver date", "prevSemverVersion": "Previous semver version"}
		self.suggestion = "This could either indicate dependency confusion or a patched vulnerability."
		self.title = "Chronological version anomaly"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a chronological version anomaly?"

	def __str__(self):
		return json.dumps(self.__dict__)


class criticalCVE:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains a Critical Common Vulnerability and Exposure (CVE)."
		self.props = {"cveId": "CVE ID", "cwes": "CWEs", "cvss": "CVSS", "description": "Description", "firstPatchedVersionIdentifier": "Patched version", "ghsaId": "GHSA ID", "id": "Id", "severity": "Severity", "title": "Title", "url": "URL", "vulnerableVersionRange": "Vulnerable versions"}
		self.suggestion = "Remove or replace dependencies that include known critical CVEs. Consumers can use dependency overrides or npm audit fix --force to remove vulnerable dependencies."
		self.title = "Critical CVE"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a critical CVE?"

	def __str__(self):
		return json.dumps(self.__dict__)


class cve:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains a high severity Common Vulnerability and Exposure (CVE)."
		self.props = {"cveId": "CVE ID", "cwes": "CWEs", "cvss": "CVSS", "description": "Description", "firstPatchedVersionIdentifier": "Patched version", "ghsaId": "GHSA ID", "id": "Id", "severity": "Severity", "title": "Title", "url": "URL", "vulnerableVersionRange": "Vulnerable versions"}
		self.suggestion = "Remove or replace dependencies that include known high severity CVEs. Consumers can use dependency overrides or npm audit fix --force to remove vulnerable dependencies."
		self.title = "High CVE"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a CVE?"

	def __str__(self):
		return json.dumps(self.__dict__)


class debugAccess:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Uses debug, reflection and dynamic code execution features."
		self.props = {"module": "Module"}
		self.suggestion = "Removing the use of debug will reduce the risk of any reflection and dynamic code execution."
		self.title = "Debug access"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is debug access?"

	def __str__(self):
		return json.dumps(self.__dict__)


class deprecated:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "The maintainer of the package marked it as deprecated. This could indicate that a single version should not be used, or that the package is no longer maintained and any new vulnerabilities will not be fixed."
		self.props = {"reason": "Reason"}
		self.suggestion = "Research the state of the package and determine if there are non-deprecated versions that can be used, or if it should be replaced with a new, supported solution."
		self.title = "Deprecated"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a deprecated package?"

	def __str__(self):
		return json.dumps(self.__dict__)


class deprecatedException:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Contains a known deprecated SPDX license exception."
		self.props = {"comments": "Comments", "exceptionId": "Exception id"}
		self.suggestion = "Fix the license so that it no longer contains deprecated SPDX license exceptions."
		self.title = "Deprecated SPDX exception"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a deprecated SPDX exception?"

	def __str__(self):
		return json.dumps(self.__dict__)


class explicitlyUnlicensedItem:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Something was found which is explicitly marked as unlicensed"
		self.props = {"location": "Location"}
		self.suggestion = "Manually review your policy on such materials"
		self.title = "Explicitly Unlicensed Item"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What do I need to know about license files?"

	def __str__(self):
		return json.dumps(self.__dict__)


class unidentifiedLicense:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Something that seems like a license was found, but its contents could not be matched with a known license"
		self.props = {"comments": "Comments", "exceptionId": "Exception id", "location": "Location"}
		self.suggestion = "Manually review the license contents."
		self.title = "Unidentified License"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What do I need to know about license files?"

	def __str__(self):
		return json.dumps(self.__dict__)


class noLicenseFound:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) License information could not be found"
		self.props = {"comments": "Comments", "exceptionId": "Exception id"}
		self.suggestion = "Manually review the licensing"
		self.title = "No License Found"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What do I need to know about license files?"

	def __str__(self):
		return json.dumps(self.__dict__)


class copyleftLicense:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Copyleft license information was found"
		self.props = {"comments": "Comments", "licenseId": "License Identifiers"}
		self.suggestion = "Determine whether use of copyleft material works for you"
		self.title = "Copyleft License"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What do I need to know about license files?"

	def __str__(self):
		return json.dumps(self.__dict__)


class nonpermissiveLicense:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) A license not known to be considered permissive was found"
		self.props = {"comments": "Comments", "licenseId": "License Identifier"}
		self.suggestion = "Determine whether use of material not offered under a known permissive license works for you"
		self.title = "Non-permissive License"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What do I need to know about license files?"

	def __str__(self):
		return json.dumps(self.__dict__)


class miscLicenseIssues:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) A package's licensing information has fine-grained problems"
		self.props = {"description": "Description", "location": "The location where the issue originates from"}
		self.suggestion = "Determine whether use of material not offered under a known permissive license works for you"
		self.title = "Nonpermissive License"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What do I need to know about license files?"

	def __str__(self):
		return json.dumps(self.__dict__)


class deprecatedLicense:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) License is deprecated which may have legal implications regarding the package's use."
		self.props = {"licenseId": "License id"}
		self.suggestion = "Update or change the license to a well-known or updated license."
		self.title = "Deprecated license"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a deprecated license?"

	def __str__(self):
		return json.dumps(self.__dict__)


class didYouMean:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package name is similar to other popular packages and may not be the package you want."
		self.props = {"alternatePackage": "Alternate package", "downloads": "Downloads", "downloadsRatio": "Download ratio", "editDistance": "Edit distance"}
		self.suggestion = "Use care when consuming similarly named packages and ensure that you did not intend to consume a different package. Malicious packages often publish using similar names as existing popular packages."
		self.title = "Possible typosquat attack"
		self.emoji = "\ud83e\uddd0"
		self.nextStepTitle = "What is a typosquat?"

	def __str__(self):
		return json.dumps(self.__dict__)


class dynamicRequire:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Dynamic require can indicate the package is performing dangerous or unsafe dynamic code execution."
		self.suggestion = "Packages should avoid dynamic imports when possible. Audit the use of dynamic require to ensure it is not executing malicious or vulnerable code."
		self.title = "Dynamic require"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is dynamic require?"

	def __str__(self):
		return json.dumps(self.__dict__)


class emptyPackage:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package does not contain any code. It may be removed, is name squatting, or the result of a faulty package publish."
		self.props = {"linesOfCode": "Lines of code"}
		self.suggestion = "Remove dependencies that do not export any code or functionality and ensure the package version includes all of the files it is supposed to."
		self.title = "Empty package"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is an empty package?"

	def __str__(self):
		return json.dumps(self.__dict__)


class envVars:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	capabilityName: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package accesses environment variables, which may be a sign of credential stuffing or data theft."
		self.props = {"envVars": "Environment variables"}
		self.suggestion = "Packages should be clear about which environment variables they access, and care should be taken to ensure they only access environment variables they claim to."
		self.title = "Environment variable access"
		self.emoji = "\u26a0\ufe0f"
		self.capabilityName = "environment"
		self.nextStepTitle = "What is environment variable access?"

	def __str__(self):
		return json.dumps(self.__dict__)


class extraneousDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package optionally loads a dependency which is not specified within any of the package.json dependency fields. It may inadvertently be importing dependencies specified by other packages."
		self.props = {"name": "Name"}
		self.suggestion = "Specify all optionally loaded dependencies in optionalDependencies within package.json."
		self.title = "Extraneous dependency"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are extraneous dependencies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class fileDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains a dependency which resolves to a file. This can obfuscate analysis and serves no useful purpose."
		self.props = {"filePath": "File path", "packageName": "Package name"}
		self.suggestion = "Remove the dependency specified by a file resolution string from package.json and update any bare name imports that referenced it before to use relative path strings."
		self.title = "File dependency"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are file dependencies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class filesystemAccess:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	capabilityName: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Accesses the file system, and could potentially read sensitive data."
		self.props = {"module": "Module"}
		self.suggestion = "If a package must read the file system, clarify what it will read and ensure it reads only what it claims to. If appropriate, packages can leave file system access to consumers and operate on data passed to it instead."
		self.title = "Filesystem access"
		self.emoji = "\u26a0\ufe0f"
		self.capabilityName = "filesystem"
		self.nextStepTitle = "What is filesystem access?"

	def __str__(self):
		return json.dumps(self.__dict__)


class gitDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains a dependency which resolves to a remote git URL. Dependencies fetched from git URLs are not immutable can be used to inject untrusted code or reduce the likelihood of a reproducible install."
		self.props = {"packageName": "Package name", "url": "URL"}
		self.suggestion = "Publish the git dependency to npm or a private package repository and consume it from there."
		self.title = "Git dependency"
		self.emoji = "\ud83c\udf63"
		self.nextStepTitle = "What are git dependencies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class gitHubDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains a dependency which resolves to a GitHub URL. Dependencies fetched from GitHub specifiers are not immutable can be used to inject untrusted code or reduce the likelihood of a reproducible install."
		self.props = {"commitsh": "Commit-ish (commit, branch, tag or version)", "githubRepo": "GitHub repo", "githubUser": "GitHub user", "packageName": "Package name"}
		self.suggestion = "Publish the GitHub dependency to npm or a private package repository and consume it from there."
		self.title = "GitHub dependency"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are GitHub dependencies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class hasNativeCode:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains native code which could be a vector to obscure malicious code, and generally decrease the likelihood of reproducible or reliable installs."
		self.suggestion = "Ensure that native code bindings are expected. Consumers may consider pure JS and functionally similar alternatives to avoid the challenges and risks associated with native code bindings."
		self.title = "Native code"
		self.emoji = "\ud83e\udee3"
		self.nextStepTitle = "What's wrong with native code?"

	def __str__(self):
		return json.dumps(self.__dict__)


class highEntropyStrings:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains high entropy strings. This could be a sign of encrypted data, leaked secrets or obfuscated code."
		self.suggestion = "Please inspect these strings to check if these strings are benign. Maintainers should clarify the purpose and existence of high entropy strings if there is a legitimate purpose."
		self.title = "High entropy strings"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are high entropy strings?"

	def __str__(self):
		return json.dumps(self.__dict__)


class homoglyphs:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains unicode homoglyphs which can be used in supply chain confusion attacks."
		self.suggestion = "Remove unicode homoglyphs if they are unnecessary, and audit their presence to confirm legitimate use."
		self.title = "Unicode homoglyphs"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are unicode homoglyphs?"

	def __str__(self):
		return json.dumps(self.__dict__)


class httpDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains a dependency which resolves to a remote HTTP URL which could be used to inject untrusted code and reduce overall package reliability."
		self.props = {"packageName": "Package name", "url": "URL"}
		self.suggestion = "Publish the HTTP URL dependency to npm or a private package repository and consume it from there."
		self.title = "HTTP dependency"
		self.emoji = "\ud83e\udd69"
		self.nextStepTitle = "What are http dependencies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class installScripts:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Install scripts are run when the package is installed. The majority of malware in npm is hidden in install scripts."
		self.props = {"script": "Script", "source": "Source"}
		self.suggestion = "Packages should not be running non-essential scripts during install and there are often solutions to problems people solve with install scripts that can be run at publish time instead."
		self.title = "Install scripts"
		self.emoji = "\ud83d\udcdc"
		self.nextStepTitle = "What is an install script?"

	def __str__(self):
		return json.dumps(self.__dict__)


class gptSecurity:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "AI has determined that this package may contain potential security issues or vulnerabilities."
		self.props = {"notes": "AI-based analysis of the package's code and behavior", "confidence": "Confidence of this analysis", "severity": "Impact of this threat"}
		self.suggestion = "An AI system identified potential security problems in this package. It is advised to review the package thoroughly and assess the potential risks before installation. You may also consider reporting the issue to the package maintainer or seeking alternative solutions with a stronger security posture."
		self.title = "AI detected security risk"
		self.emoji = "\ud83e\udd16"
		self.nextStepTitle = "What are AI detected security risks?"

	def __str__(self):
		return json.dumps(self.__dict__)


class gptAnomaly:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "AI has identified unusual behaviors that may pose a security risk."
		self.props = {"notes": "AI-based analysis of the package's code and behavior", "confidence": "Confidence of this analysis", "severity": "Impact of this threat", "risk": "Risk level"}
		self.suggestion = "An AI system found a low-risk anomaly in this package. It may still be fine to use, but you should check that it is safe before proceeding."
		self.title = "AI detected anomaly"
		self.emoji = "\ud83e\udd14"
		self.nextStepTitle = "What is an AI detected anomaly?"

	def __str__(self):
		return json.dumps(self.__dict__)


class gptMalware:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "AI has identified this package as malware. This is a strong signal that the package may be malicious."
		self.props = {"notes": "AI-based analysis of the package's code and behavior", "confidence": "Confidence of this analysis", "severity": "Impact of this behavior"}
		self.suggestion = "Given the AI system's identification of this package as malware, extreme caution is advised. It is recommended to avoid downloading or installing this package until the threat is confirmed or flagged as a false positive."
		self.title = "AI detected potential malware"
		self.emoji = "\ud83e\udd16"
		self.nextStepTitle = "What is AI detected malware?"

	def __str__(self):
		return json.dumps(self.__dict__)


class potentialVulnerability:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Initial human review suggests the presence of a vulnerability in this package. It is pending further analysis and confirmation."
		self.props = {"note": "AI detection + human review", "risk": "Risk level"}
		self.suggestion = "It is advisable to proceed with caution. Engage in a review of the package's security aspects and consider reaching out to the package maintainer for the latest information or patches."
		self.title = "Potential vulnerability"
		self.emoji = "\ud83d\udea7"
		self.nextStepTitle = "Navigating potential vulnerabilities"

	def __str__(self):
		return json.dumps(self.__dict__)


class invalidPackageJSON:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package has an invalid manifest file and can cause installation problems if you try to use it."
		self.suggestion = "Fix syntax errors in the manifest file and publish a new version. Consumers can use npm overrides to force a version that does not have this problem if one exists."
		self.title = "Invalid manifest file"
		self.emoji = "\ud83e\udd12"
		self.nextStepTitle = "What is an invalid manifest file?"

	def __str__(self):
		return json.dumps(self.__dict__)


class invisibleChars:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Source files contain invisible characters. This could indicate source obfuscation or a supply chain attack."
		self.suggestion = "Remove invisible characters. If their use is justified, use their visible escaped counterparts."
		self.title = "Invisible chars"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are invisible characters?"

	def __str__(self):
		return json.dumps(self.__dict__)


class licenseChange:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package license has recently changed."
		self.props = {"newLicenseId": "New license id", "prevLicenseId": "Previous license id"}
		self.suggestion = "License changes should be reviewed carefully to inform ongoing use. Packages should avoid making major changes to their license type."
		self.title = "License change"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a license change?"

	def __str__(self):
		return json.dumps(self.__dict__)


class licenseException:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Contains an SPDX license exception."
		self.props = {"comments": "Comments", "exceptionId": "Exception id"}
		self.suggestion = "License exceptions should be carefully reviewed."
		self.title = "License exception"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a license exception?"

	def __str__(self):
		return json.dumps(self.__dict__)


class longStrings:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains long string literals, which may be a sign of obfuscated or packed code."
		self.suggestion = "Avoid publishing or consuming obfuscated or bundled code. It makes dependencies difficult to audit and undermines the module resolution system."
		self.title = "Long strings"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What's wrong with long strings?"

	def __str__(self):
		return json.dumps(self.__dict__)


class missingTarball:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package is missing it's tarball.  It could be removed from the npm registry or there may have been an error when publishing."
		self.suggestion = "This package cannot be analyzed or installed due to missing data."
		self.title = "Missing package tarball"
		self.emoji = "\u2754"
		self.nextStepTitle = "What is a missing tarball?"

	def __str__(self):
		return json.dumps(self.__dict__)


class majorRefactor:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package has recently undergone a major refactor. It may be unstable or indicate significant internal changes. Use caution when updating to versions that include significant changes."
		self.props = {"changedPercent": "Change percentage", "curSize": "Current amount of lines", "linesChanged": "Lines changed", "prevSize": "Previous amount of lines"}
		self.suggestion = "Consider waiting before upgrading to see if any issues are discovered, or be prepared to scrutinize any bugs or subtle changes the major refactor may bring. Publishers my consider publishing beta versions of major refactors to limit disruption to parties interested in the new changes."
		self.title = "Major refactor"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a major refactor?"

	def __str__(self):
		return json.dumps(self.__dict__)


class malware:
	description: str
	props: dict
	title: str
	suggestion: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package is malware. We have asked the package registry to remove it."
		self.props = {"id": "Id", "note": "Note"}
		self.title = "Known malware"
		self.suggestion = "It is strongly recommended that malware is removed from your codebase."
		self.emoji = "\u2620\ufe0f"
		self.nextStepTitle = "What is known malware?"

	def __str__(self):
		return json.dumps(self.__dict__)


class manifestConfusion:
	description: str
	props: dict
	title: str
	suggestion: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package has inconsistent metadata. This could be malicious or caused by an error when publishing the package."
		self.props = {"key": "Key", "description": "Description"}
		self.title = "Manifest confusion"
		self.suggestion = "Packages with inconsistent metadata may be corrupted or malicious."
		self.emoji = "\ud83e\udd78"
		self.nextStepTitle = "What is manifest confusion?"

	def __str__(self):
		return json.dumps(self.__dict__)


class mediumCVE:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains a medium severity Common Vulnerability and Exposure (CVE)."
		self.props = {"cveId": "CVE ID", "cwes": "CWEs", "cvss": "CVSS", "description": "Description", "firstPatchedVersionIdentifier": "Patched version", "ghsaId": "GHSA ID", "id": "Id", "severity": "Severity", "title": "Title", "url": "URL", "vulnerableVersionRange": "Vulnerable versions"}
		self.suggestion = "Remove or replace dependencies that include known medium severity CVEs. Consumers can use dependency overrides or npm audit fix --force to remove vulnerable dependencies."
		self.title = "Medium CVE"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a medium CVE?"

	def __str__(self):
		return json.dumps(self.__dict__)


class mildCVE:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Contains a low severity Common Vulnerability and Exposure (CVE)."
		self.props = {"cveId": "CVE ID", "cwes": "CWEs", "cvss": "CVSS", "description": "Description", "firstPatchedVersionIdentifier": "Patched version", "ghsaId": "GHSA ID", "id": "Id", "severity": "Severity", "title": "Title", "url": "URL", "vulnerableVersionRange": "Vulnerable versions"}
		self.suggestion = "Remove or replace dependencies that include known low severity CVEs. Consumers can use dependency overrides or npm audit fix --force to remove vulnerable dependencies."
		self.title = "Low CVE"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a mild CVE?"

	def __str__(self):
		return json.dumps(self.__dict__)


class minifiedFile:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package contains minified code.  This may be harmless in some cases where minified code is included in packaged libraries, however packages on npm should not minify code."
		self.props = {"confidence": "Confidence"}
		self.suggestion = "In many cases minified code is harmless, however minified code can be used to hide a supply chain attack.  Consider not shipping minified code on npm."
		self.title = "Minified code"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What's wrong with minified code?"

	def __str__(self):
		return json.dumps(self.__dict__)


class missingAuthor:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "The package was published by an npm account that no longer exists."
		self.suggestion = "Packages should have active and identified authors."
		self.title = "Non-existent author"
		self.emoji = "\ud83e\udee5"
		self.nextStepTitle = "What is a non-existent author?"

	def __str__(self):
		return json.dumps(self.__dict__)


class missingDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "A required dependency is not declared in package.json and may prevent the package from working."
		self.props = {"name": "Name"}
		self.suggestion = "The package should define the missing dependency inside of package.json and publish a new version. Consumers may have to install the missing dependency themselves as long as the dependency remains missing. If the dependency is optional, add it to optionalDependencies and handle the missing case."
		self.title = "Missing dependency"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a missing dependency?"

	def __str__(self):
		return json.dumps(self.__dict__)


class missingLicense:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package does not have a license and consumption legal status is unknown."
		self.suggestion = "A new version of the package should be published that includes a valid SPDX license in a license file, package.json license field or mentioned in the README."
		self.title = "Missing license"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a missing license?"

	def __str__(self):
		return json.dumps(self.__dict__)


class mixedLicense:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package contains multiple licenses."
		self.props = {"licenseId": "License Ids"}
		self.suggestion = "A new version of the package should be published that includes a single license. Consumers may seek clarification from the package author. Ensure that the license details are consistent across the LICENSE file, package.json license field and license details mentioned in the README."
		self.title = "Mixed license"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a mixed license?"

	def __str__(self):
		return json.dumps(self.__dict__)


class ambiguousClassifier:
	props: dict
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.props = {"classifier": "The classifier"}
		self.description = "(Experimental) An ambiguous license classifier was found."
		self.suggestion = "A specific license or licenses should be identified"
		self.title = "Ambiguous License Classifier"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is an ambiguous license classifier?"

	def __str__(self):
		return json.dumps(self.__dict__)


class modifiedException:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package contains a modified version of an SPDX license exception.  Please read carefully before using this code."
		self.props = {"comments": "Comments", "exceptionId": "Exception id", "similarity": "Similarity"}
		self.suggestion = "Packages should avoid making modifications to standard license exceptions."
		self.title = "Modified license exception"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a modified license exception?"

	def __str__(self):
		return json.dumps(self.__dict__)


class modifiedLicense:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package contains a modified version of an SPDX license.  Please read carefully before using this code."
		self.props = {"licenseId": "License id", "similarity": "Similarity"}
		self.suggestion = "Packages should avoid making modifications to standard licenses."
		self.title = "Modified license"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a modified license?"

	def __str__(self):
		return json.dumps(self.__dict__)


class networkAccess:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	capabilityName: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This module accesses the network."
		self.props = {"module": "Module"}
		self.suggestion = "Packages should remove all network access that is functionally unnecessary. Consumers should audit network access to ensure legitimate use."
		self.title = "Network access"
		self.emoji = "\u26a0\ufe0f"
		self.capabilityName = "network"
		self.nextStepTitle = "What is network access?"

	def __str__(self):
		return json.dumps(self.__dict__)


class newAuthor:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "A new npm collaborator published a version of the package for the first time. New collaborators are usually benign additions to a project, but do indicate a change to the security surface area of a package."
		self.props = {"newAuthor": "New author", "prevAuthor": "Previous author"}
		self.suggestion = "Scrutinize new collaborator additions to packages because they now have the ability to publish code into your dependency tree. Packages should avoid frequent or unnecessary additions or changes to publishing rights."
		self.title = "New author"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is new author?"

	def __str__(self):
		return json.dumps(self.__dict__)


class noAuthorData:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package does not specify a list of contributors or an author in package.json."
		self.suggestion = "Add a author field or contributors array to package.json."
		self.title = "No contributors or author data"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "Why is contributor and author data important?"

	def __str__(self):
		return json.dumps(self.__dict__)


class noBugTracker:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package does not have a linked bug tracker in package.json."
		self.suggestion = "Add a bugs field to package.json. https://docs.npmjs.com/cli/v8/configuring-npm/package-json#bugs"
		self.title = "No bug tracker"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "Why are bug trackers important?"

	def __str__(self):
		return json.dumps(self.__dict__)


class noREADME:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package does not have a README. This may indicate a failed publish or a low quality package."
		self.suggestion = "Add a README to to the package and publish a new version."
		self.title = "No README"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "Why are READMEs important?"

	def __str__(self):
		return json.dumps(self.__dict__)


class noRepository:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package does not have a linked source code repository. Without this field, a package will have no reference to the location of the source code use to generate the package."
		self.suggestion = "Add a repository field to package.json. https://docs.npmjs.com/cli/v8/configuring-npm/package-json#repository"
		self.title = "No repository"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "Why are missing repositories important?"

	def __str__(self):
		return json.dumps(self.__dict__)


class noTests:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package does not have any tests. This is a strong signal of a poorly maintained or low quality package."
		self.suggestion = "Add tests and publish a new version of the package. Consumers may look for an alternative package with better testing."
		self.title = "No tests"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What does no tests mean?"

	def __str__(self):
		return json.dumps(self.__dict__)


class noV1:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package is not semver >=1. This means it is not stable and does not support ^ ranges."
		self.suggestion = "If the package sees any general use, it should begin releasing at version 1.0.0 or later to benefit from semver."
		self.title = "No v1"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is wrong with semver < v1?"

	def __str__(self):
		return json.dumps(self.__dict__)


class noWebsite:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package does not have a website."
		self.suggestion = "Add a homepage field to package.json. https://docs.npmjs.com/cli/v8/configuring-npm/package-json#homepage"
		self.title = "No website"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a missing website?"

	def __str__(self):
		return json.dumps(self.__dict__)


class nonFSFLicense:
	description: str
	props: dict
	title: str
	suggestion: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package has a non-FSF-approved license."
		self.props = {"licenseId": "License id"}
		self.title = "Non FSF license"
		self.suggestion = "Consider the terms of the license for your given use case."
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a non FSF license?"

	def __str__(self):
		return json.dumps(self.__dict__)


class nonOSILicense:
	description: str
	props: dict
	title: str
	suggestion: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package has a non-OSI-approved license."
		self.props = {"licenseId": "License id"}
		self.title = "Non OSI license"
		self.suggestion = "Consider the terms of the license for your given use case."
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a non OSI license?"

	def __str__(self):
		return json.dumps(self.__dict__)


class nonSPDXLicense:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package contains a non-standard license somewhere. Please read carefully before using."
		self.suggestion = "Package should adopt a standard SPDX license consistently across all license locations (LICENSE files, package.json license fields, and READMEs)."
		self.title = "Non SPDX license"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a non SPDX license?"

	def __str__(self):
		return json.dumps(self.__dict__)


class notice:
	description: str
	title: str
	suggestion: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package contains a legal notice. This could increase your exposure to legal risk when using this project."
		self.title = "Legal notice"
		self.suggestion = "Consider the implications of the legal notice for your given use case."
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is a legal notice?"

	def __str__(self):
		return json.dumps(self.__dict__)


class obfuscatedFile:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Obfuscated files are intentionally packed to hide their behavior.  This could be a sign of malware"
		self.props = {"confidence": "Confidence"}
		self.suggestion = "Packages should not obfuscate their code.  Consider not using packages with obfuscated code"
		self.title = "Obfuscated code"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is obfuscated code?"

	def __str__(self):
		return json.dumps(self.__dict__)


class obfuscatedRequire:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package accesses dynamic properties of require and may be obfuscating code execution."
		self.suggestion = "The package should not access dynamic properties of module. Instead use import or require directly."
		self.title = "Obfuscated require"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is obfuscated require?"

	def __str__(self):
		return json.dumps(self.__dict__)


class peerDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package specifies peer dependencies in package.json."
		self.props = {"name": "Name"}
		self.suggestion = "Peer dependencies are fragile and can cause major problems across version changes. Be careful when updating this dependency and its peers."
		self.title = "Peer dependency"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are peer dependencies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class semverAnomaly:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package semver skipped several versions, this could indicate a dependency confusion attack or indicate the intention of disruptive breaking changes or major priority shifts for the project."
		self.props = {"newVersion": "New version", "prevVersion": "Previous version"}
		self.suggestion = "Packages should follow semantic versions conventions by not skipping subsequent version numbers. Consumers should research the purpose of the skipped version number."
		self.title = "Semver anomaly"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are semver anomalies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class shellAccess:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	capabilityName: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This module accesses the system shell. Accessing the system shell increases the risk of executing arbitrary code."
		self.props = {"module": "Module"}
		self.suggestion = "Packages should avoid accessing the shell which can reduce portability, and make it easier for malicious shell access to be introduced."
		self.title = "Shell access"
		self.emoji = "\u26a0\ufe0f"
		self.capabilityName = "shell"
		self.nextStepTitle = "What is shell access?"

	def __str__(self):
		return json.dumps(self.__dict__)


class shellScriptOverride:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package re-exports a well known shell command via an npm bin script.  This is possibly a supply chain attack"
		self.props = {"binScript": "Bin script"}
		self.suggestion = "Packages should not export bin scripts which conflict with well known shell commands"
		self.title = "Bin script shell injection"
		self.emoji = "\ud83e\udd80"
		self.nextStepTitle = "What is bin script shell injection?"

	def __str__(self):
		return json.dumps(self.__dict__)


class suspiciousString:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package contains suspicious text patterns which are commonly associated with bad behavior"
		self.props = {"explanation": "Explanation", "pattern": "Pattern"}
		self.suggestion = "The package code should be reviewed before installing"
		self.title = "Suspicious strings"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are suspicious strings?"

	def __str__(self):
		return json.dumps(self.__dict__)


class telemetry:
	description: str
	props: dict
	title: str
	suggestion: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package contains telemetry which tracks how it is used."
		self.props = {"id": "Id", "note": "Note"}
		self.title = "Telemetry"
		self.suggestion = "Most telemetry comes with settings to disable it. Consider disabling telemetry if you do not want to be tracked."
		self.emoji = "\ud83d\udcde"
		self.nextStepTitle = "What is telemetry?"

	def __str__(self):
		return json.dumps(self.__dict__)


class trivialPackage:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Packages less than 10 lines of code are easily copied into your own project and may not warrant the additional supply chain risk of an external dependency."
		self.props = {"linesOfCode": "Lines of code"}
		self.suggestion = "Removing this package as a dependency and implementing its logic will reduce supply chain risk."
		self.title = "Trivial Package"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are trivial packages?"

	def __str__(self):
		return json.dumps(self.__dict__)


class troll:
	description: str
	props: dict
	title: str
	suggestion: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package is a joke, parody, or includes undocumented or hidden behavior unrelated to its primary function."
		self.props = {"id": "Id", "note": "Note"}
		self.title = "Protestware or potentially unwanted behavior"
		self.suggestion = "Consider that consuming this package my come along with functionality unrelated to its primary purpose."
		self.emoji = "\ud83e\uddcc"
		self.nextStepTitle = "What is protestware?"

	def __str__(self):
		return json.dumps(self.__dict__)


class typeModuleCompatibility:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package is CommonJS, but has a dependency which is type: \"module\".  The two are likely incompatible."
		self.suggestion = "The package needs to switch to dynamic import on the esmodule dependency, or convert to esm itself. Consumers may experience errors resulting from this incompatibility."
		self.title = "CommonJS depending on ESModule"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "Why can't CJS depend on ESM?"

	def __str__(self):
		return json.dumps(self.__dict__)


class uncaughtOptionalDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package uses an optional dependency without handling a missing dependency exception. If you install it without the optional dependencies then it could cause runtime errors."
		self.props = {"name": "Name"}
		self.suggestion = "Package should handle the loading of the dependency when it is not present, or convert the optional dependency into a regular dependency."
		self.title = "Uncaught optional dependency"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "Why are uncaught optional dependencies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class unclearLicense:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package contains a reference to a license without a matching LICENSE file."
		self.props = {"possibleLicenseId": "Possible license id"}
		self.suggestion = "Add a LICENSE file that matches the license field in package.json. https://docs.npmjs.com/cli/v8/configuring-npm/package-json#license"
		self.title = "Unclear license"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are unclear licenses?"

	def __str__(self):
		return json.dumps(self.__dict__)


class shrinkwrap:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package contains a shrinkwrap file.  This may allow the package to bypass normal install procedures."
		self.suggestion = "Packages should never use npm shrinkwrap files due to the dangers they pose."
		self.title = "NPM Shrinkwrap"
		self.emoji = "\ud83e\uddca"
		self.nextStepTitle = "What is a shrinkwrap file?"

	def __str__(self):
		return json.dumps(self.__dict__)


class unmaintained:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package has not been updated in more than 5 years and may be unmaintained. Problems with the package may go unaddressed."
		self.props = {"lastPublish": "Last publish"}
		self.suggestion = "Package should publish periodic maintenance releases if they are maintained, or deprecate if they have no intention in further maintenance."
		self.title = "Unmaintained"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are unmaintained packages?"

	def __str__(self):
		return json.dumps(self.__dict__)


class unpublished:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package version was not found on the registry. It may exist on a different registry and need to be configured to pull from that registry."
		self.props = {"version": "The version that was not found"}
		self.suggestion = "Packages can be removed from the registry by manually un-publishing, a security issue removal, or may simply never have been published to the registry. Reliance on these packages will cause problem when they are not found."
		self.title = "Unpublished package"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are unpublished packages?"

	def __str__(self):
		return json.dumps(self.__dict__)


class unresolvedRequire:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package imports a file which does not exist and may not work as is. It could also be importing a file that will be created at runtime which could be a vector for running malicious code."
		self.suggestion = "Fix imports so that they require declared dependencies or existing files."
		self.title = "Unresolved require"
		self.emoji = "\ud83d\udd75\ufe0f"
		self.nextStepTitle = "What is unresolved require?"

	def __str__(self):
		return json.dumps(self.__dict__)


class unsafeCopyright:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "(Experimental) Package contains a copyright but no license. Using this package may expose you to legal risk."
		self.suggestion = "Clarify the license type by adding a license field to package.json and a LICENSE file."
		self.title = "Unsafe copyright"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is unsafe copyright?"

	def __str__(self):
		return json.dumps(self.__dict__)


class unstableOwnership:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "A new collaborator has begun publishing package versions. Package stability and security risk may be elevated."
		self.props = {"author": "Author"}
		self.suggestion = "Try to reduce the amount of authors you depend on to reduce the risk to malicious actors gaining access to your supply chain. Packages should remove inactive collaborators with publishing rights from packages on npm."
		self.title = "Unstable ownership"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What is unstable ownership?"

	def __str__(self):
		return json.dumps(self.__dict__)


class unusedDependency:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package has unused dependencies. This package depends on code that it does not use.  This can increase the attack surface for malware and slow down installation."
		self.props = {"name": "Name", "version": "Version"}
		self.suggestion = "Packages should only specify dependencies that they use directly."
		self.title = "Unused dependency"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are unused dependencies?"

	def __str__(self):
		return json.dumps(self.__dict__)


class urlStrings:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package contains fragments of external URLs or IP addresses, which may indicate that it covertly exfiltrates data."
		self.props = {"urlFragment": "URL Fragment"}
		self.suggestion = "Avoid using packages that make connections to the network, since this helps to leak data."
		self.title = "URL strings"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are URL strings?"

	def __str__(self):
		return json.dumps(self.__dict__)


class usesEval:
	description: str
	props: dict
	suggestion: str
	title: str
	emoji: str
	capabilityName: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package uses eval() which is a dangerous function. This prevents the code from running in certain environments and increases the risk that the code may contain exploits or malicious behavior."
		self.props = {"evalType": "Eval type"}
		self.suggestion = "Avoid packages that use eval, since this could potentially execute any code."
		self.title = "Uses eval"
		self.emoji = "\u26a0\ufe0f"
		self.capabilityName = "eval"
		self.nextStepTitle = "What is eval?"

	def __str__(self):
		return json.dumps(self.__dict__)


class zeroWidth:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "Package files contain zero width unicode characters. This could indicate a supply chain attack."
		self.suggestion = "Packages should remove unnecessary zero width unicode characters and use their visible counterparts."
		self.title = "Zero width unicode chars"
		self.emoji = "\u26a0\ufe0f"
		self.nextStepTitle = "What are zero width unicode characters?"

	def __str__(self):
		return json.dumps(self.__dict__)


class floatingDependency:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str
	props: dict

	def __init__(self):
		self.description = "Package has a dependency with a floating version range.  This can cause issues if the dependency publishes a new major version."
		self.suggestion = "Packages should specify properly semver ranges to avoid version conflicts."
		self.title = "Floating dependency"
		self.emoji = "\ud83c\udf88"
		self.nextStepTitle = "What are floating dependencies?"
		self.props = {"dependency": "Dependency"}

	def __str__(self):
		return json.dumps(self.__dict__)


class unpopularPackage:
	description: str
	suggestion: str
	title: str
	emoji: str
	nextStepTitle: str

	def __init__(self):
		self.description = "This package is not very popular."
		self.suggestion = "Unpopular packages may have less maintenance and contain other problems."
		self.title = "Unpopular package"
		self.emoji = "\ud83c\udfda\ufe0f"
		self.nextStepTitle = "What are unpopular packages?"

	def __str__(self):
		return json.dumps(self.__dict__)


class AllIssues:
	badEncoding: badEncoding
	badSemver: badSemver
	badSemverDependency: badSemverDependency
	bidi: bidi
	binScriptConfusion: binScriptConfusion
	chronoAnomaly: chronoAnomaly
	criticalCVE: criticalCVE
	cve: cve
	debugAccess: debugAccess
	deprecated: deprecated
	deprecatedException: deprecatedException
	explicitlyUnlicensedItem: explicitlyUnlicensedItem
	unidentifiedLicense: unidentifiedLicense
	noLicenseFound: noLicenseFound
	copyleftLicense: copyleftLicense
	nonpermissiveLicense: nonpermissiveLicense
	miscLicenseIssues: miscLicenseIssues
	deprecatedLicense: deprecatedLicense
	didYouMean: didYouMean
	dynamicRequire: dynamicRequire
	emptyPackage: emptyPackage
	envVars: envVars
	extraneousDependency: extraneousDependency
	fileDependency: fileDependency
	filesystemAccess: filesystemAccess
	gitDependency: gitDependency
	gitHubDependency: gitHubDependency
	hasNativeCode: hasNativeCode
	highEntropyStrings: highEntropyStrings
	homoglyphs: homoglyphs
	httpDependency: httpDependency
	installScripts: installScripts
	gptSecurity: gptSecurity
	gptAnomaly: gptAnomaly
	gptMalware: gptMalware
	potentialVulnerability: potentialVulnerability
	invalidPackageJSON: invalidPackageJSON
	invisibleChars: invisibleChars
	licenseChange: licenseChange
	licenseException: licenseException
	longStrings: longStrings
	missingTarball: missingTarball
	majorRefactor: majorRefactor
	malware: malware
	manifestConfusion: manifestConfusion
	mediumCVE: mediumCVE
	mildCVE: mildCVE
	minifiedFile: minifiedFile
	missingAuthor: missingAuthor
	missingDependency: missingDependency
	missingLicense: missingLicense
	mixedLicense: mixedLicense
	ambiguousClassifier: ambiguousClassifier
	modifiedException: modifiedException
	modifiedLicense: modifiedLicense
	networkAccess: networkAccess
	newAuthor: newAuthor
	noAuthorData: noAuthorData
	noBugTracker: noBugTracker
	noREADME: noREADME
	noRepository: noRepository
	noTests: noTests
	noV1: noV1
	noWebsite: noWebsite
	nonFSFLicense: nonFSFLicense
	nonOSILicense: nonOSILicense
	nonSPDXLicense: nonSPDXLicense
	notice: notice
	obfuscatedFile: obfuscatedFile
	obfuscatedRequire: obfuscatedRequire
	peerDependency: peerDependency
	semverAnomaly: semverAnomaly
	shellAccess: shellAccess
	shellScriptOverride: shellScriptOverride
	suspiciousString: suspiciousString
	telemetry: telemetry
	trivialPackage: trivialPackage
	troll: troll
	typeModuleCompatibility: typeModuleCompatibility
	uncaughtOptionalDependency: uncaughtOptionalDependency
	unclearLicense: unclearLicense
	shrinkwrap: shrinkwrap
	unmaintained: unmaintained
	unpublished: unpublished
	unresolvedRequire: unresolvedRequire
	unsafeCopyright: unsafeCopyright
	unstableOwnership: unstableOwnership
	unusedDependency: unusedDependency
	urlStrings: urlStrings
	usesEval: usesEval
	zeroWidth: zeroWidth
	floatingDependency: floatingDependency
	unpopularPackage: unpopularPackage
	def __init__(self):
		self.badEncoding = badEncoding()
		self.badSemver = badSemver()
		self.badSemverDependency = badSemverDependency()
		self.bidi = bidi()
		self.binScriptConfusion = binScriptConfusion()
		self.chronoAnomaly = chronoAnomaly()
		self.criticalCVE = criticalCVE()
		self.cve = cve()
		self.debugAccess = debugAccess()
		self.deprecated = deprecated()
		self.deprecatedException = deprecatedException()
		self.explicitlyUnlicensedItem = explicitlyUnlicensedItem()
		self.unidentifiedLicense = unidentifiedLicense()
		self.noLicenseFound = noLicenseFound()
		self.copyleftLicense = copyleftLicense()
		self.nonpermissiveLicense = nonpermissiveLicense()
		self.miscLicenseIssues = miscLicenseIssues()
		self.deprecatedLicense = deprecatedLicense()
		self.didYouMean = didYouMean()
		self.dynamicRequire = dynamicRequire()
		self.emptyPackage = emptyPackage()
		self.envVars = envVars()
		self.extraneousDependency = extraneousDependency()
		self.fileDependency = fileDependency()
		self.filesystemAccess = filesystemAccess()
		self.gitDependency = gitDependency()
		self.gitHubDependency = gitHubDependency()
		self.hasNativeCode = hasNativeCode()
		self.highEntropyStrings = highEntropyStrings()
		self.homoglyphs = homoglyphs()
		self.httpDependency = httpDependency()
		self.installScripts = installScripts()
		self.gptSecurity = gptSecurity()
		self.gptAnomaly = gptAnomaly()
		self.gptMalware = gptMalware()
		self.potentialVulnerability = potentialVulnerability()
		self.invalidPackageJSON = invalidPackageJSON()
		self.invisibleChars = invisibleChars()
		self.licenseChange = licenseChange()
		self.licenseException = licenseException()
		self.longStrings = longStrings()
		self.missingTarball = missingTarball()
		self.majorRefactor = majorRefactor()
		self.malware = malware()
		self.manifestConfusion = manifestConfusion()
		self.mediumCVE = mediumCVE()
		self.mildCVE = mildCVE()
		self.minifiedFile = minifiedFile()
		self.missingAuthor = missingAuthor()
		self.missingDependency = missingDependency()
		self.missingLicense = missingLicense()
		self.mixedLicense = mixedLicense()
		self.ambiguousClassifier = ambiguousClassifier()
		self.modifiedException = modifiedException()
		self.modifiedLicense = modifiedLicense()
		self.networkAccess = networkAccess()
		self.newAuthor = newAuthor()
		self.noAuthorData = noAuthorData()
		self.noBugTracker = noBugTracker()
		self.noREADME = noREADME()
		self.noRepository = noRepository()
		self.noTests = noTests()
		self.noV1 = noV1()
		self.noWebsite = noWebsite()
		self.nonFSFLicense = nonFSFLicense()
		self.nonOSILicense = nonOSILicense()
		self.nonSPDXLicense = nonSPDXLicense()
		self.notice = notice()
		self.obfuscatedFile = obfuscatedFile()
		self.obfuscatedRequire = obfuscatedRequire()
		self.peerDependency = peerDependency()
		self.semverAnomaly = semverAnomaly()
		self.shellAccess = shellAccess()
		self.shellScriptOverride = shellScriptOverride()
		self.suspiciousString = suspiciousString()
		self.telemetry = telemetry()
		self.trivialPackage = trivialPackage()
		self.troll = troll()
		self.typeModuleCompatibility = typeModuleCompatibility()
		self.uncaughtOptionalDependency = uncaughtOptionalDependency()
		self.unclearLicense = unclearLicense()
		self.shrinkwrap = shrinkwrap()
		self.unmaintained = unmaintained()
		self.unpublished = unpublished()
		self.unresolvedRequire = unresolvedRequire()
		self.unsafeCopyright = unsafeCopyright()
		self.unstableOwnership = unstableOwnership()
		self.unusedDependency = unusedDependency()
		self.urlStrings = urlStrings()
		self.usesEval = usesEval()
		self.zeroWidth = zeroWidth()
		self.floatingDependency = floatingDependency()
		self.unpopularPackage = unpopularPackage()
