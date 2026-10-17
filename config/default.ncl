let certs_config = import "inspectors/certs/default.ncl" in
{
	schema_version = 1,
	inspectors = {
		certs = certs_config,
	},
}
