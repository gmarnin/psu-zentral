resource "zentral_santa_configuration" "default" {
  name           = "PSU MacAdmins 2024 Default"
  client_mode    = "MONITOR"
  enable_bundles = true
}

resource "zentral_santa_enrollment" "default" {
  configuration_id      = zentral_santa_configuration.default.id
  meta_business_unit_id = zentral_meta_business_unit.default.id
}
