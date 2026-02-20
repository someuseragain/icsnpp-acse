#include "config.h"
#include "Plugin.h"
#include "Analyzer.h"

#include <zeek/analyzer/Component.h>

using namespace zeek;

namespace zeek::plugin::acse {

Plugin plugin;

zeek::plugin::Configuration Plugin::Configure()
{
	zeek::plugin::Configuration config;

	config.name = "OSS::ACSE";
	config.description = "";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;

    static const std::string simple_name="ACSE";
    static const std::string iso_name=util::canonify_name("ISO:2.2.1.0.1");

    AddComponent(
        new zeek::analyzer::Component(
            simple_name,
            [](zeek::Connection *c) -> zeek::analyzer::Analyzer* {return new Analyzer(simple_name.c_str(), c);}
        )
    );
    AddComponent(
        new zeek::analyzer::Component(
            iso_name,
            [](zeek::Connection *c) -> zeek::analyzer::Analyzer* {return new Analyzer(iso_name.c_str(), c);}
        )
    );

	return config;
}

} // namespace zeek::plugin::acse
