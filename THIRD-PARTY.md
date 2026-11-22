# Third-party licenses

Swift Package Manager fetches the dependencies pinned in
[`host/Package.resolved`](host/Package.resolved). Each dependency keeps its
own license and notices. [`SWIFTPM-LICENSES.tsv`](SWIFTPM-LICENSES.tsv) lists
the upstream license file and its SHA-256 for each pinned revision. Some
projects include additional terms or notices alongside the listed file.
When redistributing dependencies, retain their applicable licenses and
notices.

The initial Swift rules in `.gitignore` come from GitHub's
[`Swift.gitignore` template](https://github.com/github/gitignore/blob/eeb775f7cbd229e8cd487ef06a1176dc239201d9/Swift.gitignore)
under [CC0-1.0](https://github.com/github/gitignore/blob/eeb775f7cbd229e8cd487ef06a1176dc239201d9/LICENSE).
