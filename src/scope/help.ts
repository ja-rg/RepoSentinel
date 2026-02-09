export default function showHelp() {
    console.log(`RepoSentinel - A tool to scan your repositories for secrets and sensitive information.

Usage:
  scanrepo [options] <path>
Options:
  -h, --help    Show this help message and exit
Examples:
  scanrepo .           Scan the current directory
  scanrepo /path/to/repo  Scan a specific repository
`);

}