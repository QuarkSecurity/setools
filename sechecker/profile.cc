/**
 *  @file
 *  Implements the public interface for sechecker module profiles.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include "sechecker.hh"

#include <apol/util.h>

#include <string>
#include <map>
#include <vector>
#include <stdexcept>
#include <libxml/xmlreader.h>
#include <cstdlib>

using std::invalid_argument;
using std::out_of_range;
using std::runtime_error;
using std::pair;
using std::string;
using std::map;
using std::vector;

namespace sechk
{
	profile::module_specification::module_specification(const std::string & name_,
							    output_format output) throw(std::invalid_argument):_options()
	{
		if (name_ == "")
			throw invalid_argument("Module name may not be empty");
		if (output <= SECHK_OUTPUT_NONE || output > SECHK_OUTPUT_MAX)
			throw invalid_argument("Invalid output mode requested");
		_name = name_;
		_output_mode = output;
	}

	profile::module_specification::module_specification(const module_specification & rhs)
	{
		_name = rhs._name;
		_output_mode = rhs._output_mode;
		_options = rhs._options;
	}

	profile::module_specification::~module_specification()
	{
		//nothing to do
	}

	output_format profile::module_specification::outputMode() const
	{
		return _output_mode;
	}

	const std::string & profile::module_specification::name() const
	{
		return _name;
	}

	void profile::module_specification::addOption(const std::string & name_,
						      const std::vector < std::string > &vals) throw(std::invalid_argument)
	{
		option opt(name_, "", vals);
		pair < map < string, option >::iterator, bool > retv = _options.insert(make_pair(name_, opt));
		if (!retv.second)
			throw invalid_argument("Cannot insert duplicate option");
	}

	const std::map < std::string, option > &profile::module_specification::options() const
	{
		return _options;
	}

	/**
	 * Given a C string return the corresponding output_format.
	 * @param str The string representing the output format.
	 * @return The corresponding output_format for \a str.
	 */
	static output_format strtoof(const char *str)
	{
		if (!strcmp(str, "default"))
			return SECHK_OUTPUT_DEFAULT;
		else if (!strcmp(str, "quiet"))
			return SECHK_OUTPUT_QUIET;
		else if (!strcmp(str, "short"))
			return SECHK_OUTPUT_SHORT;
		else if (!strcmp(str, "verbose"))
			return SECHK_OUTPUT_VERBOSE;
		else
			return SECHK_OUTPUT_NONE;
	}

      profile::profile(const std::string & path)throw(std::runtime_error):_mod_specs()
	{
		_version = "";
		_name = "";
		_description = "";
		xmlDtdPtr dtd = NULL;
		xmlDocPtr xml = NULL;
		xmlValidCtxtPtr ctxt = NULL;

		LIBXML_TEST_VERSION;
		char *dtd_path = apol_file_find_path("sechecker/sechecker.dtd");
		if (!dtd_path)
			throw runtime_error("Could not find profile DTD");
		string dtd_uri = "file:///";
		dtd_uri += dtd_path;
		free(dtd_path);

		dtd = xmlParseDTD(NULL, reinterpret_cast < const xmlChar * >(dtd_uri.c_str()));
		if (!dtd)
			throw runtime_error("Could not parse DTD");
		xml = xmlParseFile(path.c_str());
		if (!xml)
		{
			xmlFreeDtd(dtd);
			throw runtime_error("Error parsing profile");
		}
		ctxt = xmlNewValidCtxt();
		if (!ctxt)
		{
			xmlFreeDoc(xml);
			xmlFreeDtd(dtd);
			throw runtime_error("Could not create validation context");
		}

		int retv = xmlValidateDtd(ctxt, xml, dtd);
		xmlFreeValidCtxt(ctxt);
		xmlFreeDoc(xml);
		xmlFreeDtd(dtd);
		if (!retv)
			throw runtime_error("Profile contains invalid XML");

		xmlTextReaderPtr reader = xmlReaderForFile(path.c_str(), NULL, 0);
		if (!reader)
			throw runtime_error("Could not create XML reader");

		module_specification *cur_mod = NULL;
		vector < string > items;
		string option_name = "";
		while ((retv = xmlTextReaderRead(reader)))
		{
			if (retv == -1)
				throw runtime_error("Error reading profile");

			switch (xmlTextReaderNodeType(reader))
			{
			case XML_ELEMENT_DECL:
			{
				const xmlChar *tag_name = xmlTextReaderConstName(reader);
				if (xmlStrEqual(tag_name, reinterpret_cast < const xmlChar * >("module")) == 1)
				{
					pair < map < string, module_specification >::iterator, bool > x =
						_mod_specs.insert(make_pair(cur_mod->name(), *cur_mod));
					if (!x.second)
					{
						string message = "Could not add specification for module " + cur_mod->name();
						delete cur_mod;
						throw runtime_error(message);
					}
					delete cur_mod;
					cur_mod = NULL;
				}
				else if (xmlStrEqual(tag_name, reinterpret_cast < const xmlChar * >("option")) == 1)
				{
					cur_mod->addOption(option_name, items);
					option_name = "";
					items.clear();
				}
				break;
			}
			case XML_ELEMENT_NODE:
			{
				const xmlChar *tag_name = xmlTextReaderConstName(reader);
				if (xmlStrEqual(tag_name, reinterpret_cast < const xmlChar * >("sechecker")) == 1)
				{
					xmlChar *version =
						xmlTextReaderGetAttribute(reader, reinterpret_cast < const xmlChar * >("version"));
					if (!version)
						throw runtime_error("Invalid sechecker tag");
					double v = atof(reinterpret_cast < const char *>(version));
					if (!v)
						throw runtime_error("Invalid version specified");
					if (v < 2.00 || v > atof(SECHECKER_VERSION))
						throw runtime_error("Profile specifies an incompatible version number");
					_version = string(reinterpret_cast < const char *>(version));
					free(version);
				}
				else if (xmlStrEqual(tag_name, reinterpret_cast < const xmlChar * >("profile")) == 1)
				{
					xmlChar *name =
						xmlTextReaderGetAttribute(reader, reinterpret_cast < const xmlChar * >("name"));
					if (!name)
						throw runtime_error("Invalid profile tag");
					_name = string(reinterpret_cast < const char *>(name));
					free(name);
				}
				else if (xmlStrEqual(tag_name, reinterpret_cast < const xmlChar * >("desc")) == 1)
				{
					char *desc = reinterpret_cast < char *>(xmlTextReaderReadString(reader));
					if (desc)
						_description += desc;
					free(desc);
					if (_description.empty())
						throw runtime_error("Invalid profile description");
					//strip leading and trailing newlines if present
					if (*(_description.begin()) == '\n')
						_description.erase(_description.begin());
					if (*(_description.end() - 1) == '\n')
						_description.erase(_description.end() - 1);
				}
				else if (xmlStrEqual(tag_name, reinterpret_cast < const xmlChar * >("module")) == 1)
				{
					xmlChar *name =
						xmlTextReaderGetAttribute(reader, reinterpret_cast < const xmlChar * >("name"));
					xmlChar *outp =
						xmlTextReaderGetAttribute(reader, reinterpret_cast < const xmlChar * >("output"));
					if (cur_mod || !name || !outp)
						throw runtime_error("Invalid module tag");
					output_format outf = strtoof(reinterpret_cast < const char *>(outp));
					cur_mod = new module_specification(string(reinterpret_cast < const char *>(name)), outf);
					free(name);
					free(outp);
				}
				else if (xmlStrEqual(tag_name, reinterpret_cast < const xmlChar * >("option")) == 1)
				{
					xmlChar *name =
						xmlTextReaderGetAttribute(reader, reinterpret_cast < const xmlChar * >("name"));
					if (!cur_mod || !name)
						throw runtime_error("Invalid option tag");
					option_name = string(reinterpret_cast < const char *>(name));
					free(name);
				}
				else if (xmlStrEqual(tag_name, reinterpret_cast < const xmlChar * >("item")) == 1)
				{
					xmlChar *val =
						xmlTextReaderGetAttribute(reader, reinterpret_cast < const xmlChar * >("value"));
					if (!cur_mod || option_name == "" || !val)
						throw runtime_error("Invalid item tag");
					items.push_back(string(reinterpret_cast < const char *>(val)));
					free(val);
				}
				break;
			}
			}
		}

		xmlCleanupParser();
		xmlFreeTextReader(reader);
	}

	profile::profile(const profile & rhs):_mod_specs(rhs._mod_specs)
	{
		_name = rhs._name;
		_version = rhs._version;
		_description = rhs._description;
	}

	profile::~profile()
	{
		//nothing to do
	}

	const std::vector < std::string > profile::getModuleList() const
	{
		vector < string > v;

		for (map < string, module_specification >::const_iterator i = _mod_specs.begin(); i != _mod_specs.end(); i++)
		{
			v.push_back(i->first);
		}

		return v;
	}

	const std::string & profile::name() const
	{
		return _name;
	}

	const std::string & profile::version() const
	{
		return _version;
	}

	const std::string & profile::description() const
	{
		return _description;
	}

	void profile::apply(sechecker & top) const throw(std::invalid_argument, std::out_of_range)
	{
		for (map < string, module_specification >::const_iterator i = _mod_specs.begin(); i != _mod_specs.end(); i++)
		{
			map < string, pair < module *, void * > >::iterator iter = top.modules().find(i->first);
			if (iter == top.modules().end())
				throw out_of_range("No module named " + i->first + " exists");
			module *mod = iter->second.first;
			mod->outputMode(i->second.outputMode());
			for (map < string, option >::const_iterator j = i->second.options().begin(); j != i->second.options().end();
			     j++)
			{
				mod->setOption(j->first, j->second.values(), true);
			}
		}
	}
}
