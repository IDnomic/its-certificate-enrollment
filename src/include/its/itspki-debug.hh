#ifndef ITS_PKI_DEBUG_HH
#define ITS_PKI_DEBUG_HH

#include <boost/iostreams/stream.hpp>

#define STREAMC_LINE_HEADER __FILE__ << " +" << __LINE__ << ": " << CLASS_NAME << "::" << __FUNCTION__ << "() "
#define STREAM_LINE_HEADER __FILE__ << " +" << __LINE__ << ": " << "::" << __FUNCTION__ << "() "

#ifdef ITS_PKI_DEBUG
	#define DEBUGC_STREAM std::cout << STREAMC_LINE_HEADER
	#define DEBUGC_STREAM_CALLED         DEBUGC_STREAM << "called" << std::endl
	#define DEBUGC_STREAM_RETURNS_OK     DEBUGC_STREAM << "returns OK" << std::endl
	
	#define DEBUG_STREAM std::cout << STREAM_LINE_HEADER
	#define DEBUG_STREAM_CALLED         DEBUG_STREAM << "called" << std::endl
	#define DEBUG_STREAM_RETURNS_OK     DEBUG_STREAM << "returns OK" << std::endl
#else
	extern boost::iostreams::stream< boost::iostreams::null_sink > nullOstream;
	#define DEBUGC_STREAM nullOstream
	#define DEBUGC_STREAM_CALLED
	#define DEBUGC_STREAM_RETURNS_OK
	
	#define DEBUG_STREAM nullOstream
	#define DEBUG_STREAM_CALLED
	#define DEBUG_STREAM_RETURNS_OK
#endif

#define ERROR_STREAMC std::cerr << STREAMC_LINE_HEADER 
#define ERROR_STREAM std::cerr << STREAM_LINE_HEADER 
#define CURL_STREAM std::cout
#define REPORT_PRINT_RECORD

#endif // ifndef ITS_PKI_DEBUG_HH
