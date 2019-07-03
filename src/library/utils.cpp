// https://gist.github.com/a2e0040d301bf4b8ef8101c0b1e3f1d5.git
#include <string>
#include <iostream>
#include <memory>
#include <cstdio>

#include "its/utils.hh"

// #include <stdarg.h>  // For va_start, etc.

bool
json_get_tag_value(const std::string &json_str, const char *name, std::string &ret)
{
	std::string nm = std::string("\"") + name + "\"";
        std::size_t found = json_str.find(nm);
        if (found == std::string::npos)
		return false;
	found = json_str.find(":", found + nm.length());
        if (found == std::string::npos)
		return false;
	found = json_str.find("\"", found + 1);
        if (found == std::string::npos)
		return false;

	std::size_t value_beg = found + 1;
        std::size_t value_end = json_str.find("\"", value_beg);
        if (value_end == std::string::npos)
		return false;

        ret = json_str.substr(value_beg, value_end - value_beg);
	return true;
}


std::string
string_format(const std::string fmt, ...) {
    int size = ((int)fmt.size()) * 2 + 50;   // Use a rubric appropriate for your code
    std::string str;
    va_list ap;
    while (1) {     // Maximum two passes on a POSIX system...
        str.resize(size);
        va_start(ap, fmt);
        int n = vsnprintf((char *)str.data(), size, fmt.c_str(), ap);
        va_end(ap);
        if (n > -1 && n < size) {  // Everything worked
            str.resize(n);
            return str;
        }
        if (n > -1)  // Needed size returned
            size = n + 1;   // For null char
        else
            size *= 2;      // Guess at a larger size (OS specific)
    }
    return str;
}


bool
read_bytes(const std::string& path_to_file, OCTETSTRING &ret)
{
        const char *filename = path_to_file.c_str();

        FILE * filp = fopen(filename, "rb");
        if (!filp) {
                std::cerr << "Cannot open file " << filename << " for reading." << std::endl;
                return false;
        }

        fseek(filp, 0L, SEEK_END);
        unsigned int fsize = ftell(filp);
        fseek(filp, 0L, SEEK_SET);

        unsigned char *buffer = (unsigned char *)malloc(fsize);
        if (!buffer)   {
                fclose(filp);
                std::cerr << "Cannot read file " << filename << " for reading." << std::endl;
                return false;
        }
        if (fread(buffer, sizeof(unsigned char), fsize, filp) != fsize)   {
                fclose(filp);
                std::cerr << "Cannot read file " << filename << " for reading." << std::endl;
                return false;
        }
        fclose(filp);

        ret = OCTETSTRING(fsize, buffer);
        free(buffer);
        return true;
}


int
writeToFile(const char *filename, const unsigned char *data, size_t len)
{
  int ret = -1;
  FILE *f = NULL;

  if (!filename)
    goto done;

  f = fopen(filename, "wb");
  if (f == NULL)   {
    fprintf(stderr, "Ecriture du fichier %s impossible.\n", filename);
    goto done;
  }

  if (data && len > 0)   {
    if (fwrite(data, 1, len, f) != len)   {
        fprintf(stderr, "Cannot write to file '%s'\n", filename);
        goto done;
    }
  }

  ret = 0;

done:
  if (f) fclose(f);
  return ret;
}


std::string
getEnvVar(std::string const &key)
{
	char * val = getenv( key.c_str() );
	return val == NULL ? std::string("") : std::string(val);
}
