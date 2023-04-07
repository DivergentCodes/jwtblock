package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"divergent.codes/jwt-block/internal/core"
	"divergent.codes/jwt-block/web"
)

var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Serve the web API",
		Long:  `Serve the web API`,
		Run:   serve,
	}
)

func init() {

	// http.hostname
	defaultHost := viper.GetString(core.OptStr_HttpHostname)
	serveCmd.Flags().String("hostname", defaultHost, "Hostname to listen on")
	viper.BindPFlag(core.OptStr_HttpHostname, serveCmd.Flags().Lookup("hostname"))

	// http.port
	defaultPort := viper.GetInt(core.OptStr_HttpPort)
	serveCmd.Flags().IntP("port", "p", defaultPort, "TCP port to listen on")
	viper.BindPFlag(core.OptStr_HttpPort, serveCmd.Flags().Lookup("port"))

	// http.status_on_allowed
	defaultStatusAllowed := viper.GetInt(core.OptStr_HttpStatusOnAllowed)
	serveCmd.Flags().Int("status-on-allowed", defaultStatusAllowed, "HTTP response code when token is allowed")
	viper.BindPFlag(core.OptStr_HttpStatusOnAllowed, serveCmd.Flags().Lookup("status-on-allowed"))

	// http.status_on_blocked
	defaultStatusBlocked := viper.GetInt(core.OptStr_HttpStatusOnBlocked)
	serveCmd.Flags().Int("status-on-blocked", defaultStatusBlocked, "HTTP response code when token is blocked")
	viper.BindPFlag(core.OptStr_HttpStatusOnBlocked, serveCmd.Flags().Lookup("status-on-blocked"))

	rootCmd.AddCommand(serveCmd)
}

func serve(cmd *cobra.Command, args []string) {
	ShowBanner()

	host := viper.GetString(core.OptStr_HttpHostname)
	port := viper.GetInt(core.OptStr_HttpPort)
	fmt.Printf("Serving the jwt-block web API on %s:%d\n", host, port)
	web.HandleRequests(host, port)
}
