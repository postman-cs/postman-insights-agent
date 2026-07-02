package apidump

var (
	reverseProxyListenFlag              string
	reverseProxyUpstreamFlag            string
	reverseProxyTLSCertFlag             string
	reverseProxyTLSKeyFlag              string
	reverseProxyUpstreamTLSInsecureFlag bool
)

func init() {
	Cmd.Flags().StringVar(
		&reverseProxyListenFlag,
		"reverse-proxy-listen",
		"",
		"Run a capturing reverse proxy on this address, e.g. ':16789'. Route service traffic through this listener to capture HTTPS or HTTP/2 traffic that passive capture cannot see.",
	)

	Cmd.Flags().StringVar(
		&reverseProxyUpstreamFlag,
		"reverse-proxy-upstream",
		"",
		"Base URL the reverse proxy forwards traffic to, e.g. 'https://127.0.0.1:8443'. Required with --reverse-proxy-listen.",
	)

	Cmd.Flags().StringVar(
		&reverseProxyTLSCertFlag,
		"reverse-proxy-tls-cert",
		"",
		"PEM certificate used by the reverse proxy to terminate TLS. If unset, the proxy listens for plaintext HTTP.",
	)

	Cmd.Flags().StringVar(
		&reverseProxyTLSKeyFlag,
		"reverse-proxy-tls-key",
		"",
		"PEM private key paired with --reverse-proxy-tls-cert.",
	)

	Cmd.Flags().BoolVar(
		&reverseProxyUpstreamTLSInsecureFlag,
		"reverse-proxy-upstream-insecure",
		false,
		"Skip verification of the upstream's TLS certificate, e.g. for self-signed in-cluster certificates.",
	)
}
