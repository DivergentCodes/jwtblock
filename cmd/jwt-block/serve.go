package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/divergentcodes/jwt-block/internal/cache"
	"github.com/divergentcodes/jwt-block/internal/core"
	"github.com/divergentcodes/jwt-block/web"
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

	var err error

	// http.hostname
	defaultHost := viper.GetString(core.OptStr_HttpHostname)
	serveCmd.Flags().String("hostname", defaultHost, "Hostname to listen on")
	err = viper.BindPFlag(core.OptStr_HttpHostname, serveCmd.Flags().Lookup("hostname"))
	if err != nil {
		panic(err)
	}

	// http.port
	defaultPort := viper.GetInt(core.OptStr_HttpPort)
	serveCmd.Flags().IntP("port", "p", defaultPort, "TCP port to listen on")
	err = viper.BindPFlag(core.OptStr_HttpPort, serveCmd.Flags().Lookup("port"))
	if err != nil {
		panic(err)
	}

	// http.status_on_allowed
	defaultStatusAllowed := viper.GetInt(core.OptStr_HttpStatusOnAllowed)
	serveCmd.Flags().Int("status-on-allowed", defaultStatusAllowed, "HTTP response code when token is allowed")
	err = viper.BindPFlag(core.OptStr_HttpStatusOnAllowed, serveCmd.Flags().Lookup("status-on-allowed"))
	if err != nil {
		panic(err)
	}

	// http.status_on_blocked
	defaultStatusBlocked := viper.GetInt(core.OptStr_HttpStatusOnBlocked)
	serveCmd.Flags().Int("status-on-blocked", defaultStatusBlocked, "HTTP response code when token is blocked")
	err = viper.BindPFlag(core.OptStr_HttpStatusOnBlocked, serveCmd.Flags().Lookup("status-on-blocked"))
	if err != nil {
		panic(err)
	}

	rootCmd.AddCommand(serveCmd)
}

func serve(cmd *cobra.Command, args []string) {
	ShowBanner()
	_, err := cache.IsRedisReady()
	if err != nil {
		panic(err)
	}

	host := viper.GetString(core.OptStr_HttpHostname)
	port := viper.GetInt(core.OptStr_HttpPort)
	fmt.Printf("Serving the jwt-block web API on %s:%d\n", host, port)
	web.HandleRequests(host, port)
}
