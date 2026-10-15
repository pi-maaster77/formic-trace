let Sha256 =
  std.contract.from_predicate (fun value =>
    std.is_string value
    && std.string.is_match "^[0-9a-fA-F]{64}$" value
  )
in

let Baseline = import "inspectors/certs/baseline.toml" in

let CertificatePolicy = {
  mode | [| 'minimal, 'purge_all, 'whitelist, 'blacklist, 'alert_only |],
  baseline_sha256 | Array Sha256,
  allow_sha256 | Array Sha256,
  deny_sha256 | Array Sha256,
  deny_issuer_name_sha256 | Array Sha256,
  allow_destructive | Bool,
  allow_import | Bool,
  import_certificates | Array String,
}
in

{
  mode = 'alert_only,
  baseline_sha256 = Baseline.baseline_sha256,
  allow_sha256 = [],
  deny_sha256 = [],
  deny_issuer_name_sha256 = [],
  allow_destructive = false,
  allow_import = false,
  import_certificates = [],
} | CertificatePolicy