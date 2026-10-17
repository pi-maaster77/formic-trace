let certs_config = import "inspectors/certs/default.ncl" in
let environment_config = import "inspectors/environment/default.ncl" in
{
	schema_version = 1,
	inspectors = {
		certs = certs_config,
		environment = environment_config,
	},
}
