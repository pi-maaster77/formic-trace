let certs_config = import "inspectors/certs/default.ncl" in
let hardware_config = import "inspectors/hardware/default.ncl" in
let identity_config = import "inspectors/identity/default.ncl" in
let system_features_config = import "inspectors/system_features/default.ncl" in
{
	schema_version = 1,
	inspectors = {
		certs = certs_config,
		environment = import "inspectors/environment/default.ncl",
		filesystem = import "inspectors/filesystem/default.ncl",
		hardware = hardware_config,
		identity = identity_config,
		registry = import "inspectors/registry/default.ncl",
		services = import "inspectors/services/default.ncl",
		system_features = system_features_config,
		tasks = import "inspectors/tasks/default.ncl",
	},
	policies = {
		kernel_drivers = import "policies/kernel_drivers/default.ncl",
		lsa = import "policies/lsa/default.ncl",
		network = import "policies/network/default.ncl",
		processes = import "policies/processes/default.ncl",
		sessions = import "policies/sessions/default.ncl",
		tokens = import "policies/tokens/default.ncl",
		wmi = import "policies/wmi/default.ncl",
	},
}
