package utcommon

// Para ...
// @Description:
//
type Para struct {
	// InterfaceName ...
	InterfaceName string `help:"interfaceName" short:"i" default:"wg1"`
	// SmartGatePort ...
	SmartGatePort string `help:"smart gate port" short:"s" default:"28880"`
	// H2CPort ...
	H2CPort string `help:"H2C port" short:"p" default:"13030"`
}
