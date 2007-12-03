/**
 * @file
 * Main function and command line parser for the sechecker program.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
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

#include <apol/policy.h>

#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <cassert>
#include <iomanip>

#include <getopt.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define COPYRIGHT_INFO "Copyright (C) 2005-2007 Tresys Technology, LLC"

using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::ios_base;
using std::invalid_argument;
using std::runtime_error;
using std::ifstream;
using std::setw;

using namespace sechk;

enum opt_values
{
	OPT_FCFILE = 256, OPT_MIN_SEV
};

/* command line options struct */
static struct option const longopts[] = {
 {"list", no_argument, NULL, 'l'},
 {"help", optional_argument, NULL, 'h'},
 {"version", no_argument, NULL, 'V'},
 {"quiet", no_argument, NULL, 'q'},
 {"short", no_argument, NULL, 's'},
 {"verbose", no_argument, NULL, 'v'},
 {"profile", required_argument, NULL, 'p'},
 {"fcfile", required_argument, NULL, OPT_FCFILE},
 {"module", required_argument, NULL, 'm'},
 {"min-sev", required_argument, NULL, OPT_MIN_SEV},
 {NULL, 0, NULL, 0}
};

/* display usage help */
void usage(const char *arg0, bool brief)
{
	printf("Usage: sechecker [OPTIONS] -p profile [POLICY ...]\n");
	printf("       sechecker [OPTIONS] -m module [POLICY ...]\n");
	printf("       sechecker [OPTIONS] -p profile -m module [POLICY ...]\n");
	printf("\n");
	if (brief) {
		printf("\tTry %s --help for more help.\n\n", arg0);
	} else {
		printf("Perform modular checks on a SELinux policy.\n");
		printf("\n");
		printf("   -p PROF, --profile=PROF      name or path of profile to load\n");
		printf("                                if used without -m, run all modules in profile\n");
		printf("   -m MODULE, --module=MODULE   MODULE to run\n");
		printf("   --fcfile=FILE                file_contexts file to load\n");
		printf("\n");
		printf("   -q, --quiet                  suppress output\n");
		printf("   -s, --short                  print short output\n");
		printf("   -v, --verbose                print verbose output\n");
		printf("   --min-sev={low|med|high}     set the minimum severity to report\n");
		printf("\n");
		printf("   -l, --list                   print a list of profiles and modules and exit\n");
		printf("   -h[MODULE], --help[=MODULE]  print this help text or help for MODULE\n");
		printf("   -V, --version                print version information and exit\n");
		printf("\n");
	}
}

static void print_list(sechecker & top)
{
	string profile_path = PROFILE_INSTALL_DIR;
	DIR* profile_dir = opendir(profile_path.c_str());
	if (!profile_dir)
	{
		throw ios_base::failure("Could not open profile directory (" + profile_path + ")");
	}
	while (dirent * ent = readdir(profile_dir))
	{
		struct stat info;
		stat(ent->d_name, &info);
		// skip things that are not regular files
		if (!S_ISREG(info.st_mode))
			continue;
		string path = profile_path + (profile_path[profile_path.length() -1] == '/'? "" : "/") + ent->d_name;
		// check that it is a profile, currently this means the first line is a sechecker XML tag
		ifstream test(path.c_str());
		char buff[256] = {0};
		test.getline(buff, 255, '\n');
		test.close();
		if (string(buff).find("<sechecker") == 0)
		{
			profile prof(path);
			top.addProfile(prof);
			continue;
		}
		// not a profile, could be a module; try to load it
		if (path.find(".so") == path.length() - 3)
		{
			// remove the .so
			string name = ent->d_name;
			name.erase(name.end() - 3, name.end());
			// load it
			top.loadModule(name);
		}
	}
	closedir(profile_dir);

	//done loading known profiles and modules; begin printing
	cout << "Profiles:" << endl;
	for (map<string, profile>::const_iterator i = top.profiles().begin(); i != top.profiles().end(); i++)
	{
		cout << "    " << setw(20) << i->first << setw(56) << i->second.description() << endl;
	}
	cout << "Modules:" << endl;
	for (map<string, pair<module*, void*> >::const_iterator i = top.modules().begin(); i != top.modules().end(); i++)
	{
		cout << "    " << setw(20) << i->first << setw(56) << i->second.first->description() << endl;
	}
}

static severity strtosev(std::string str)
{
	if (str == "high")
		return SECHK_SEV_HIGH;
	else if (str == "med")
		return SECHK_SEV_MED;
	else if (str == "low")
		return SECHK_SEV_LOW;
	else
		return SECHK_SEV_NONE;
}

/**
 * Attempt to locate a profile by name.
 * First check the profile install directory, if not found assume raw path.
 * @param name Name of the profile to find.
 * @return Path to the profile if found, \a name otherwise.
 */
static const string find_profile(const string & name)
{
	string test_path = PROFILE_INSTALL_DIR;
	test_path += name;
	test_path += ".profile";
	if (access(test_path.c_str(), R_OK))
	{
		return name;
	}
	return test_path;
}

/* main application */
int main(int argc, char **argv)
{
	string prof_name = ""; //profile to use
	string single_mod = ""; //set if single module (-m) is specified
	string fcpath = ""; //fcfile to load
	severity min_sev = SECHK_SEV_NONE; //minimum severity for the report
	output_format outf = SECHK_OUTPUT_NONE; //output format for the report
	bool module_help = false;
	bool list_stop = false;

	int optc;
	while ((optc = getopt_long(argc, argv, "p:m:qsvlh::V", longopts, NULL)) != -1)
	{
		switch (optc)
		{
			case 'p':
			{
				prof_name = optarg;
				break;
			}
			case 'm':
			{
				if (min_sev)
				{
					cerr << "Error: Cannot specify minimum severity and single module." << endl;
					exit(EXIT_FAILURE);
				}
				single_mod = optarg;
				break;
			}
			case OPT_FCFILE:
			{
				fcpath = optarg;
				break;
			}
			case 'q':
			{
				if (outf)
				{
					cerr << "Error: Multiple output formats requested." << endl;
					usage(argv[0], true);
					exit(EXIT_FAILURE);
				}
				outf = SECHK_OUTPUT_QUIET;
				break;
			}
			case 's':
			{
				if (outf)
				{
					cerr << "Error: Multiple output formats requested." << endl;
					usage(argv[0], true);
					exit(EXIT_FAILURE);
				}
				outf = SECHK_OUTPUT_SHORT;
				break;
			}
			case 'v':
			{
				if (outf)
				{
					cerr << "Error: Multiple output formats requested." << endl;
					usage(argv[0], true);
					exit(EXIT_FAILURE);
				}
				outf = SECHK_OUTPUT_VERBOSE;
				break;
			}
			case OPT_MIN_SEV:
			{
				if (single_mod != "")
				{
					cerr << "Error: Cannot specify minimum severity and single module." << endl;
					exit(EXIT_FAILURE);
				}
				min_sev = strtosev(optarg);
				if (!min_sev)
				{
					cerr << "Error: Invalid minimum severity " << optarg << " specified." << endl;
					exit(EXIT_FAILURE);
				}
				break;
			}
			case 'l':
			{
				list_stop = true;
				break;
			}
			case 'h':
			{
				if (optarg != NULL) {
					single_mod = optarg;
					module_help = true;
					break;
				}
				usage(argv[0], false);
				exit(EXIT_SUCCESS);
			}
			case 'V':
			{
				cout << "sechecker " << SECHECKER_VERSION << endl;
				cout << COPYRIGHT_INFO << endl;
				exit(EXIT_SUCCESS);
			}
			default:
			{
				usage(argv[0], true);
				exit(EXIT_FAILURE);
			}
		}
	}

	if (single_mod == "" && prof_name == "" && !list_stop)
	{
		cerr << "Error: No profile or module specified." << endl;
		exit(EXIT_FAILURE);
	}

	//initialize sechecker top level controller
	sechecker top;

	// if list reqested print it and exit
	if (list_stop)
	{
		print_list(top);
		top.close();
		exit(EXIT_SUCCESS);
	}

	// if a single module was specified load it
	if (single_mod != "")
	{
		try
		{
			top.loadModule(single_mod);
		}
		catch (ios_base::failure x) // failed loading module
		{
			cerr << x.what() << endl;
			top.close();
			exit(EXIT_FAILURE);
		}
		// if loaded only for help, print that and exit
		if (module_help)
		{
			top.modules().at(single_mod).first->help(cout);
			top.close();
			exit(EXIT_SUCCESS);
		}
	}

	// if a profile is specified load it and all modules it mentions
	profile* prof = NULL;
	if (prof_name != "")
	{
		try
		{
			string prof_path = find_profile(prof_name);
			prof = new profile(prof_path);
		}
		catch (runtime_error x) // failed opening profile
		{
			cerr << x.what() << endl;
			top.close();
			delete prof;
			exit(EXIT_FAILURE);
		}
		top.addProfile(*prof);
		// load the modules in the profile
		const vector<string> mods = prof->getModuleList();
		for (vector<string>::const_iterator i = mods.begin(); i != mods.end(); i++)
		{
			try
			{
			top.loadModule(*i);
			}
			catch (ios_base::failure x) // failed loading module
			{
				cerr << x.what() << endl;
				top.close();
				delete prof;
				exit(EXIT_FAILURE);
			}
		}
		// activate the profile
		try
		{
			top.activeProfile(prof->name());
		}
		catch (invalid_argument x) // invalid profile arguments
		{
			cerr << x.what() << endl;
			top.close();
			delete prof;
			exit(EXIT_FAILURE);
		}
		delete prof; // done with local copy
	}

	// load any module dependencies (calling load multiple times for the same module is essentially a no-op)
	const map<string, pair<module*, void*> > loaded_mods = top.modules();
	for (map<string, pair<module*, void*> >::const_iterator i = loaded_mods.begin(); i != loaded_mods.end(); i++)
	{
		const vector<string> deps = i->second.first->dependencies();
		for (vector<string>::const_iterator j = deps.begin(); j != deps.end(); j++)
		{
			top.loadModule(*j);
		}
	}

	report* rep = NULL;
	try
	{
		if (single_mod != "")
		{
			top.runModules(single_mod);
			if (outf != SECHK_OUTPUT_QUIET)
			{
				rep = top.createReport(single_mod);
			}
		}
		else
		{
			top.runModules();
			if (outf != SECHK_OUTPUT_QUIET)
			{
				rep = top.createReport();
			}
		}
		assert(rep || outf == SECHK_OUTPUT_QUIET);
		if (outf != SECHK_OUTPUT_QUIET)
		{
			if (min_sev != SECHK_SEV_NONE)
			{
				rep->minSev(min_sev);
			}
			if (outf != SECHK_OUTPUT_NONE)
			{
				rep->outputMode(outf);
			}
			rep->print(cout);
			delete rep;
		}
	}
	catch (runtime_error x) // error running module or creating report
	{
		cerr << x.what() << endl;
		top.close();
		delete rep;
		exit(EXIT_FAILURE);
	}

	top.close();
	delete rep;
	return 0;
}
