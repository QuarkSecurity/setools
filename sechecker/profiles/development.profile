<sechecker version="2.0">
<profile name="development">
<desc>
Run common development modules.
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

<module name="attribs_wo_types" output="short">
</module>

<module name="roles_wo_types" output="short">
</module>

<module name="users_wo_roles" output="short">
</module>

<module name="roles_wo_allow" output="short">
</module>

<module name="types_wo_allow" output="short">
</module>

<module name="attribs_wo_rules" output="short">
</module>

<module name="roles_wo_users" output="short">
</module>

<module name="spurious_audit" output="verbose">
</module>

<module name="domains_wo_roles" output="short">
</module>

</profile>
</sechecker>