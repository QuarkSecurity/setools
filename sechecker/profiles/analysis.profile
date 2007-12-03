<sechecker version="2.0">
<profile name="analysis">
<desc>
Run common analysis modules.
</desc>

<module name="find_domains" output="quiet">
	<option name="domain_attribute">
		<item value="domain"/>
	</option>
</module>

<module name="find_file_types" output="quiet">
	<option name="file_type_attribute">
		<item value="file_type"/>
	</option>
</module>

<module name="domain_and_file" output="short">
</module>

<module name="spurious_audit" output="verbose">
</module>

<module name="inc_mount" output="verbose">
</module>

<module name="domains_wo_roles" output="short">
</module>

<module name="inc_dom_trans" output="short">
</module>

<module name="find_net_domains" output="quiet">
	<option name="net_obj">
		<item value="netif"/>
		<item value="tcp_socket"/>
		<item value="udp_socket"/>
		<item value="node"/>
		<item value="association"/>
	</option>
</module>

<module name="find_port_types" output="quiet">
</module>

<module name="find_node_types" output="quiet">
</module>

<module name="find_netif_types" output="quiet">
</module>

<module name="inc_net_access" output="short">
</module>

<module name="imp_range_trans" output="short">
</module>

<module name="unreachable_doms" output="short">
</module>

</profile>
</sechecker>