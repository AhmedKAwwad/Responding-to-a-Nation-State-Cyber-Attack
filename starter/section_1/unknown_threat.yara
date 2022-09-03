rule threat{
	meta:
		author = "Ahmed K. Awwad"
		description = "Yara rule for unknown threat detection"

	strings:
		$url1 = "http://darkl0rd.com:7758/SSH-T"
		$url2 = "http://darkl0rd.com:7758/SSH-One"
		$command1 = "iptables stop"
		$command2 = "iptables off"

	condition:
		all of them
}