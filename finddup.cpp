/*
   finddup - find duplicate files
   Copyright (c) 2004-2021 Steve Connet. All Rights Reserved.

   This program will perform an md5 checksum of all the files in the specified
   directory tree. It will print the duplicate files.

   HEURISTICS
   1. Search for same file size; if match goto step 2
   2. Search first 64 bytes of file; if match goto step 3
   3. Search last 64 bytes of file; if match goto step 4
   4. Perform SHA1; if match record duplicate

   Compile with:
   g++ -O2 -o finddup finddup.cpp -lssl
   gcc -O2 -o finddup finddup.cpp -lssl -lc

   MacOS now uses clang. Compile with:
   clang++ -O2 -std=c++11 -o finddup finddup.cpp \
   $(pkg-config --libs --cflags libssl)


HISTORY:
2014-06-15 - updated for osx uses sha1 instead of deprecated md5
2021-03-13 - filter using heuristics
*/

#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <vector>
#include <chrono>   // C++11

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <limits.h>

#define NDEBUG
#include <assert.h>

#if defined(__APPLE__)
#  define COMMON_DIGEST_FOR_OPENSSL
#  include <CommonCrypto/CommonDigest.h>
#  define SHA1 CC_SHA1
#else
#  include <openssl/sha.h>
#endif

char const *const version =
"finddup v1.2  Copyright (c) 2014-2021 Steve Connet. All Rights Reserved.";

char const *const usage =
"Usage is: finddup [OPTIONS] PATH\n"
"            -r    recurse into subdirs\n"
"            -q    quiet mode (overrides -s)\n"
"            -s    show files being scanned\n"
"            -V    version\n"
"            -h    help\n"
"            -u    usage\n";

#define NONE     0x0000
#define RECURSE  0x0001  // recurse into subdirs
#define QUIET    0x0002  // suppress verbosity
#define SHOWSCAN 0x0004  // display file being scanned

// needs to be evenly divisible by 4
#define MATCH_BYTES    (64)
#define MATCH_BYTES_X2 (MATCH_BYTES * 2)

static size_t options = NONE;
static size_t directories = 1; // +1 for starting directory
static size_t digest_files = 0;
static size_t symlinks = 0;
static size_t max_file_sz = 0;
static size_t min_file_sz = ULLONG_MAX; // limits.h
static size_t total_bytes_in_path = 0;

//-----------------------------------------------------------------------------
//
//  CONTAINER RELATIONSHIPS
//
//-----------------------------------------------------------------------------
//
// Container of a list of filepaths that have the same file size.
typedef std::vector<std::string> PathList;
//
// Commonly used list of indices into the path list.
typedef std::vector<size_t> IndexList;
//
// Key  : file size
// Value: list of file paths
typedef std::map<size_t, IndexList> SizeDB;
//
//  Size Map - All files with the same size are put into their own list (we
//  store the index into the Path list and not the file path itself).
//
//             +--------+
//             | file 1 |-+
//  map -----> | file 2 | |-+               1. Sort by size
//             | file x | | |
//             +--------+ | |
//                +-------+ |
//                   +------+
//
//-----------------------------------------------------------------------------
//
// Container of a list of filepath iterators in which each file has the same
// checksum of the first 64 bytes in the file.
//
typedef std::pair<size_t, size_t> SizeChecksum;
//
// Key  : pair<file size, checksum of some bytes in file>
// Value: list of iterators to file path in file path list
typedef std::map<SizeChecksum, IndexList> TopMatchDB;
//
//  TopMatch Map - We open and read the first 64 bytes of each path name in
//  each list in the Size map. We perform a checksum on these bytes and put
//  files with the same check into their own lists.
//
//                 +---------+
//                 | index 1 |-+
//  map ---------> | index 2 | |-+          2. Match top 64 bytes
//                 | index x | | |
//                 +---------+ | |
//                    +--------+ |
//                       +-------+
//
//-----------------------------------------------------------------------------
//
// Container of a list of filepath iterators in which each file has the same
// checksum of the last 64 bytes in the file.
//
// Key  : pair<file size, checksum of some bytes in file>
// Value: list of iterators to file path in file path list
typedef std::map<SizeChecksum, IndexList> BottomMatchDB;
//
//  BottomMatch Map - We open and read the last 64 bytes of each path name in
//  each list in the TopMatch map. We perform a checksum on these bytes and
//  put files with the same check into their own lists.
//
//                +---------+
//                | index 1 |-+
//  map --------> | index 2 | |-+           3. Match Bottom 64 bytes
//                | index x | | |
//                +---------+ | |
//                   +--------+ |
//                      +-------+
//
//-----------------------------------------------------------------------------
//
// key: checksum, value: vector of iterators
// Container of a list of filepath iterators in which each file has the same
// checksum of the last 64 bytes in the file.
//
// Key  : pair<file size, checksum of some bytes in file>
// Value: list of iterators to file path in file path list
typedef std::map<std::string, IndexList> DigestDB;
//
//  DigestMatch Map - We perform a DIGEST on all bytes of each path name in
//  each list in the BottomMatch map. We put files with the same DIGEST into
//  their own lists.
//
//                +---------+
//                | index 1 |-+
//  map --------> | index 2 | |-+           4. Match DIGESTs
//                | index x | | |
//                +---------+ | |
//                   +--------+ |
//                      +-------+
//
//  Any list in the DigestMatch Map that has more than 1 element are file
//  matches. Inform user of duplicate files.
//
//-----------------------------------------------------------------------------

PathList path_list;
SizeDB size_db;
TopMatchDB top_db;
BottomMatchDB bottom_db;
DigestDB digest_db;

std::string clearstr;

/*-----------------------------------------------------------------------------
 *  Class Stopwatch - measured elapsed time
 *
 * Construction starts the stopwatch. Call microseconds() to return the
 * elapsed time since construction, or since the mark() method was called.
 *-----------------------------------------------------------------------------
 */
class Stopwatch
{
    public:
        // Construct and start this stopwatch (calls mark)
        Stopwatch(void);

        // Mark a new start time, forgetting about previous start times
        void mark(void);

        // Return the elapsed time since latest mark
        template <typename units>
            unsigned long elapsed(void) const;

        // Return the elapsed time as a convenient string with resonable units
        std::string elapsedStr();

    protected:
        std::chrono::time_point<std::chrono::steady_clock> start;
};

/*-----------------------------------------------------------------------------
 *  ctor Stopwatch
 *
 *-----------------------------------------------------------------------------
 */
Stopwatch::Stopwatch(void)
{
    mark();
}

/*-----------------------------------------------------------------------------
 *  method Stopwatch::mark
 *
 *-----------------------------------------------------------------------------
 */
void Stopwatch::mark(void)
{
    start = std::chrono::steady_clock::now();
}

/*-----------------------------------------------------------------------------
 *  method Stopwatch::elapsed
 *
 *-----------------------------------------------------------------------------
 */
template <typename units>
unsigned long Stopwatch::elapsed(void) const
{
    return std::chrono::duration_cast<units>(std::chrono::steady_clock::now()
            - start).count();
}

/*-----------------------------------------------------------------------------
 *  method Stopwatch::elapsedStr
 *
 *-----------------------------------------------------------------------------
 */
std::string Stopwatch::elapsedStr()
{
    double total;
    std::ostringstream oss;
    std::string units;

    // in terms of microseconds
    size_t const milliseconds = 1e3;
    size_t const seconds = 1e6;
    size_t const minutes = seconds * 60;
    size_t const hours = minutes * 60;
    size_t const days = hours * 24;

    unsigned long microseconds = elapsed<std::chrono::microseconds>();

    if (microseconds < milliseconds) // stay in microseconds
    {
        total = microseconds;
        units = " microsecond";
    }
    else if (microseconds < seconds) // can be expressed in milliseconds
    {
        total = microseconds / (milliseconds + 0.0f);
        units = " millisecond";
    }
    else if (microseconds < minutes) // can be expressed in seconds
    {
        total = microseconds / (seconds + 0.0f);
        units = " second";
    }
    else if (microseconds < hours)   // can be expressed in minutes
    {
        total = microseconds / (minutes + 0.0f);
        units = " minute";
    }
    else if (microseconds < days)    // express in hours
    {
        total = microseconds / (hours + 0.0f);
        units = " hour";
    }
    else // if (microseconds < weeks) // express in days
    {
        total = microseconds / (days + 0.0f);
        units = " day";
    }

    oss << total << units;

    // make plural if needed
    if (total > 1)
    {
        oss << 's';
    }

    return oss.str();
}

/*-----------------------------------------------------------------------------
 *  function clearLine
 *
 *-----------------------------------------------------------------------------
 */
void clearLine(std::ostream &out)
{
    out << '\r' << clearstr << '\r';
}

/*-----------------------------------------------------------------------------
 *  function calcChecksum
 *
 *-----------------------------------------------------------------------------
 */
size_t calcChecksum(char const *data, size_t bytes)
{
    size_t checksum = 0;

    // ensure evenly divisible by 4
    assert(0 == (bytes % 4));
    size_t const dwords = (MATCH_BYTES / sizeof(uint32_t));

    uint32_t const *p = reinterpret_cast<uint32_t const *>(data);

    for (size_t i = 0; i < dwords; ++i)
    {
        checksum += p[i];
    }

    return checksum;
}

/*-----------------------------------------------------------------------------
 *  function fileOpen
 *
 *  Prints an error to stderr if file open failed
 *
 *-----------------------------------------------------------------------------
 */
template <typename T>
size_t candidates(T container)
{
    size_t num_candidates = 0;

    for (auto p = container.begin(); p != container.end(); ++p)
    {
        auto num_files = p->second.size();
        if (num_files > 1)
        {
            num_candidates += num_files;
        }
    }

    return num_candidates;
}

/*-----------------------------------------------------------------------------
 *  function fileOpen
 *
 *  Prints an error to stderr if file open failed
 *
 *-----------------------------------------------------------------------------
 */
FILE *fileOpen(const char *file, const char *mode)
{
    FILE *f = fopen(file, mode);
    if (NULL == f)
    {
        std::cerr << "Skipping and excluding file " << file
            << " due to an open error. REF 1. ";
        if (errno != 0)
        {
            std::cerr << strerror(errno);
        }

        std::cerr << std::endl;
    }

    return f;
}

/*-----------------------------------------------------------------------------
 *  function smartSizeStr
 *
 *  Given a size in bytes, returns a string containing the value in adjusted
 *  units with a units type.
 *
 *-----------------------------------------------------------------------------
 */
std::string smartSizeStr(size_t bytes)
{
#if 0
    // Metric
    size_t const multiplier = 1000;
    size_t const kilobyte  = multiplier;
    size_t const megabyte  = kilobyte * multiplier;
    size_t const gigabyte  = megabyte * multiplier;
    size_t const terabyte  = gigabyte * multiplier;
    size_t const petabyte  = terabyte * multiplier;
    size_t const exabyte   = petabyte * multiplier;
    size_t const zetabyte  = exabyte  * multiplier;
    size_t const yottabyte = zetabyte * multiplier;
#endif

    // ISO/IEC 80000
    size_t const kibibyte  = (1UL << 10); // 10 bits
    size_t const mebibyte  = (1UL << 20); // 20 bits
    size_t const gibibyte  = (1UL << 30); // 30 bits
    size_t const tebibyte  = (1UL << 40); // 40 bits
    size_t const pebibyte  = (1UL << 50); // 50 bits
    size_t const exbibyte  = (1UL << 60); // 60 bits
#if 0
    size_t const zebibytes = (1 << 70); // 70 bits
    size_t const yeibyte   = (1 << 80); // 80 bits
#endif

    std::ostringstream oss;
    double total;
    std::string units;

    if (bytes < kibibyte)          // stay in bytes
    {
        total = bytes;
        units = " byte";
    }
    else if (bytes < mebibyte)    // express in kibibytes
    {
        total = bytes / (kibibyte + 0.0f);
        units = " kibibyte";
    }
    else if (bytes < gibibyte)    // express in mebibytes
    {
        total = bytes / (mebibyte + 0.0f);
        units = " mebibyte";
    }
    else if (bytes < tebibyte)    // express in gibibytes
    {
        total = bytes / (gibibyte + 0.0f);
        units = " gibibyte";
    }
    else if (bytes < pebibyte)    // express in tebibytes
    {
        total = bytes / (tebibyte + 0.0f);
        units = " tebibyte";
    }
    else if (bytes < exbibyte)    // express in pebibytes
    {
        total = bytes / (pebibyte + 0.0f);
        units = " pebibyte";
    }
    else // if (bytes < zebibyte) // express in exbibytes
    {
        total = bytes / (exbibyte + 0.0f);
        units = " exbibyte";
    }

    oss << total << units;

    // make plural if needed
    if (0 == total || total > 1)
    {
        oss << 's';
    }

    return oss.str();
}

/*-----------------------------------------------------------------------------
 *  function performDigest
 *
 * Calculate digest on this filel and add to the digest list.
 *
 *-----------------------------------------------------------------------------
 */
void performDigest(char const *file, size_t size, size_t index)
{
    char md_value[SHA_DIGEST_LENGTH];
    size_t max_allocated_size = 0;
    char *data = NULL;

    FILE *f = fileOpen(file, "rb");
    if (f != NULL)
    {
        // allocate enough CPU RAM so we can read in the entire file
        if (size > max_allocated_size)
        {
            max_allocated_size = size;
            if (NULL == data)
            {
                data = new (std::nothrow) char[size];
                if (NULL == data)
                {
                    std::cerr << "Skipping and excluding file "
                        << file << " due to a memory allocation error."
                        << " Failed to allocate " << size << " bytes. REF 2.";
                    if (errno != 0)
                    {
                        std::cerr << strerror(errno);
                    }
                    std::cerr << std::endl;
                }
            }
            else
            {
                data = reinterpret_cast<char *>(realloc(data, size));
                if (NULL == data)
                {
                    std::cerr << "Skipping and excluding file "
                        << file << " due to a memory reallocation error."
                        << " Failed to reallocate " << size
                        << " bytes. REF 3.";
                    if (errno != 0)
                    {
                        std::cerr << strerror(errno);
                    }
                    std::cerr << std::endl;
                }
            }
        }

        // read entire file into CPU RAM
        size_t bytes = fread(data, 1, size, f);
        if (bytes != size)
        {
            std::cerr << "Skipping and excluding file " << file
                << " due to a read error. Read " << bytes << " bytes"
                << " but expected to read " << size << " bytes. REF 4.";
            if (errno != 0)
            {
                std::cerr << strerror(errno);
            }
            std::cerr << std::endl;
        }
        else
        {
            // extern unsigned char *CC_SHA1(const void *data, CC_LONG len,
            // unsigned char *md);
            CC_SHA1(data, size, reinterpret_cast<unsigned char *>(md_value));

            // put in digest
            std::string digest_str(md_value);

            // create new index list if this isn't already in the digest
            if (digest_db.find(digest_str) == digest_db.end())
            {
                digest_db[digest_str] = IndexList();
            }

            // add digest
            digest_db[digest_str].push_back(index);
            ++digest_files;
        }

        fclose(f);
    }

    delete []data;
    data = NULL;
}

/*-----------------------------------------------------------------------------
 *  function scanPath
 *
 * Scan all files starting at the path specified. Filter all files with the
 * same size and add them to s1dups for further filtering.
 *
 *-----------------------------------------------------------------------------
 */
bool scanPath(char const *path)
{
    bool result = true;
    std::ostringstream oss;

    DIR *dir = opendir(path);

    if (NULL == dir)
    {
        std::cerr << "\nFailed to open dir: " << path << std::endl;
        result = false;
    }
    else
    {
        struct dirent *dirent = readdir(dir);
        while (dirent != NULL)
        {
            // skip files . and ..
            if ((strcmp(".", dirent->d_name) != 0) &&
                    (strcmp("..", dirent->d_name) != 0))
            {
                // create full pathname
                std::string pathname = path;
                pathname += '/';
                pathname += dirent->d_name;

                // let user know what we are doing
                if (!(options & QUIET) && (options & SHOWSCAN))
                {
                    clearLine(std::cerr);
                    oss.str("");
                    oss << "Scanning " << path;
                    //                    oss << "Scanning " << pathname;
                    std::cerr << oss.str() << std::flush;
                    clearstr = std::string(oss.str().size(), ' ');
                }

                // get file metadata
                struct stat buf;
                if (lstat(pathname.c_str(), &buf) < 0)
                {
                    std::cerr << "\nFailed to stat " << pathname << std::endl;
                    result = false;
                    break;
                }

                // S_ISLNK(m)  symbolic link?  (Not in POSIX.1-1996.)
                // skip symlinks (count them for metrics)
                if (!(options & QUIET) && S_ISLNK(buf.st_mode))
                {
                    ++symlinks;
                }

                // recursively scan directories
                else if ((options & RECURSE) && S_ISDIR(buf.st_mode))
                {
                    result = scanPath(pathname.c_str());
                    if (false == result)
                    {
                        break;
                    }
                    else
                    {
                        if (!(options & QUIET))
                        {
                            ++directories;
                        }
                    }
                }

                // only capture regular files
                else if (S_ISREG(buf.st_mode))
                {
                    if (!(options & QUIET))
                    {
                        // collect some interesting metrics
                        total_bytes_in_path += buf.st_size;
                        if (buf.st_size > max_file_sz)
                        {
                            max_file_sz = buf.st_size;
                        }
                        else if (buf.st_size < min_file_sz)
                        {
                            min_file_sz = buf.st_size;
                        }
                    }

                    // File is too small. We won't be checksumming any bytes
                    // in this file, so just Add to digest now.
                    if (buf.st_size <= MATCH_BYTES_X2)
                    {
                        // the ordering of the following two statements is
                        // important - adding to path_list must be last
                        size_t index = path_list.size();
                        path_list.push_back(pathname);
                        performDigest(pathname.c_str(), buf.st_size, index);
                    }
                    else
                    {
                        // see if there is already a list for this file size
                        auto p = size_db.find(buf.st_size);
                        if (size_db.end() == p)
                        {
                            // new size - create empty list
                            size_db[buf.st_size] = IndexList();
                        }

                        // the ordering of the following two statements is
                        // important - adding to path_list must be last

                        // add index to list for this size file
                        size_db[buf.st_size].push_back(path_list.size());

                        // capture file path
                        path_list.push_back(pathname);
                    }
                }
                else
                {
                    // skip dirs if not recurse and skip symbolic links
                    //printf("Skipping %lld %s.\n", buf.st_size, pathname.c_str());
                }
            }

            // get next entry in the directory
            dirent = readdir(dir);

        } // while
    }

    if (!(options & QUIET) && (options & SHOWSCAN))
    {
        clearLine(std::cerr);
    }

    closedir(dir);
    return result;
}

/*-----------------------------------------------------------------------------
 *  function scanTopBytes
 *
 * Filter s1dups by reading the first 64 bytes of each file. The ones
 * that match each other are put into s2dups for furthur filtering.
 *
 * Instead of checking each byte by byte, we'll simplify by doing a checksum
 * instead.
 *
 * PRE: all files in size_db are guaranteed to be larger than 128 bytes
 *
 *-----------------------------------------------------------------------------
 */
void scanTopBytes(void)
{
    char data[MATCH_BYTES];
    uint32_t checksum = 0;
    FILE *f = NULL;

    // go through each list of file sizes
    for (auto p = size_db.begin(); p != size_db.end(); ++p)
    {
        // only scan files with duplicate sizes
        if (p->second.size() > 1)
        {
            // convenience aliases
            size_t const &size = p->first;
            IndexList const &indices = p->second;

            // go through each file for this size
            for (auto q = p->second.begin(); q != p->second.end(); ++q)
            {
                auto index = *q;
                std::string const &file = path_list[index];

                FILE *f = fileOpen(file.c_str(), "rb");
                if (f != NULL)
                {
                    size_t bytes = fread(data, 1, MATCH_BYTES, f);
                    if (bytes != MATCH_BYTES)
                    {
                        std::cerr << "Skipping and excluding file "
                            << file << " due to a read error. Read "
                            << bytes << " bytes but expected to read "
                            << MATCH_BYTES << " bytes. REF 5.";
                        if (errno != 0)
                        {
                            std::cerr << strerror(errno);
                        }
                        std::cerr << std::endl;
                    }
                    else
                    {
                        // Perform checksum
                        checksum = calcChecksum(data, MATCH_BYTES);

                        // put checksum in map with original iterator from Size
                        SizeChecksum key = std::make_pair(size, checksum);

                        // see if there is already a list for this file size
                        if (top_db.find(key) == top_db.end())
                        {
                            // new key - create empty list
                            top_db[key] = IndexList();
                        }

                        // add index to list for this size/checksum pair
                        top_db[key].push_back(index);

                    } // fread

                    fclose(f);

                } // fileOpen
            } // go through each file
        } // only read duplicate files
    } // end file size iteration
} // scanTopBytes

/*-----------------------------------------------------------------------------
 *  function scanBottomBytes
 *
 * Filter s2dups by reading the last 64 bytes of each file. The ones that
 * match each other are put into s3dups for furthur filtering.
 *
 * PRE: all files in top_db are guaranteed to be larger than 128 bytes
 *
 *-----------------------------------------------------------------------------
 */
void scanBottomBytes(void)
{
    char data[MATCH_BYTES];
    uint32_t checksum = 0;
    FILE *f = NULL;

    // go through each list of top matches and check bottoms
    for (auto p = top_db.begin(); p != top_db.end(); ++p)
    {
        // only scan files with duplicate sizes
        if (p->second.size() > 1)
        {
            // convenience aliases
            SizeChecksum const &key = p->first;
            IndexList const &indices = p->second;

            size_t const &size = key.first;
            size_t const &num_indices = indices.size();

            // go through each file
            for (auto q = p->second.begin(); q != p->second.end(); ++q)
            {
                auto index = *q;
                std::string const &file = path_list[index];

                FILE *f = fileOpen(file.c_str(), "rb");
                if (f != NULL)
                {
                    // scan to end of file minus 64 bytes
                    int ok = fseeko(f, -MATCH_BYTES, SEEK_END);
                    if (ok != 0)
                    {
                        std::cerr << "Skipping and excluding file "
                            << file << " due to a fseeko error. REF 6.";
                        if (errno != 0)
                        {
                            std::cerr << strerror(errno);
                        }
                        std::cerr << std::endl;
                    }
                    else
                    {
                        size_t bytes = fread(data, 1, MATCH_BYTES, f);
                        if (bytes != MATCH_BYTES)
                        {
                            std::cerr << "Skipping and excluding file "
                                << file << " due to a read error. Read "
                                << bytes << " bytes but expected to read "
                                << MATCH_BYTES << " bytes. REF 7.";
                            if (errno != 0)
                            {
                                std::cerr << strerror(errno);
                            }
                            std::cerr << std::endl;
                        }
                        else
                        {
                            // Perform checksum
                            checksum = calcChecksum(data, MATCH_BYTES);

                            // put checksum in map with original iterator
                            // from Size
                            SizeChecksum key =
                                std::make_pair(size, checksum);

                            // see if there is already a list for this
                            // file size, checksum pair
                            if (bottom_db.find(key) == bottom_db.end())
                            {
                                // new key - create empty list
                                bottom_db[key] = IndexList();
                            }

                            // add index to list for this size/checksum
                            // pair
                            bottom_db[key].push_back(index);

                        } // fread
                    } // fseek

                    fclose(f);

                } // fileOpen
            } // go through each file
        } // only read duplicate files
    } // end top matches iteration
} // scanBottomBytes

/*-----------------------------------------------------------------------------
 *  function processArguments
 *
 *-----------------------------------------------------------------------------
 */
bool processArguments(int argc, char *argv[])
{
    bool ok = true;
    int c;

    while ((true == ok) && (c = getopt(argc, argv, ":rqsVhu")) != -1)
    {
        switch (c)
        {
            case 'r':
                options |= RECURSE;
                break;

            case 'q':
                options |= QUIET;
                break;

            case 's':
                options |= SHOWSCAN;
                break;

            case 'V':
                std::cout << version << std::endl;
                ok = false;
                break;

            case 'h':
                std::cout << "TODO: Display help here." << std::endl;
                ok = false;
                break;

            case 'u':
                ok = false;
                break;

            default:
                std::cout << usage << std::endl;
                ok = false;
                break;
        }
    }

    return ok;
}

/*-----------------------------------------------------------------------------
 *  function search
 *
 * DEVNOTE: Files with size less than or equal to 128 bytes were put into the
 * digest_db and will not be used in stage 2, 3, or 4 for byte matching.
 *-----------------------------------------------------------------------------
 */
bool search(char const *path)
{
    bool result = EXIT_FAILURE;

    //--- STAGE 1 SCAN --------------------------------------------------------
    Stopwatch sw;

    // find stage 1 duplicates - file size duplicates
    if (!(options & QUIET))
    {
        std::cout << "Scanning files; please wait..." << std::endl;
    }

    if (true == scanPath(path))
    {
        size_t num_size_db = 0;
        size_t num_top_db = 0;
        size_t num_bottom_db = 0;
        size_t total_files = path_list.size();

        result = EXIT_SUCCESS;

        if (!(options & QUIET))
        {
            std::cout << "Scanned " << total_files << " files in "
                << directories << " directories totaling "
                << smartSizeStr(total_bytes_in_path) << ".\n";
            std::cout << "Smallest file encountered was "
                << smartSizeStr(min_file_sz) << ".\n";
            std::cout << "Largest file encountered was "
                << smartSizeStr(max_file_sz) << '.' << std::endl;

            if (symlinks > 0)
            {
                std::cout << "Of those scanned, ignoring " << symlinks
                    << " symlink";
                if (symlinks > 1)
                {
                    std::cout << 's';
                }
                std::cout << '.' << std::endl;
            }

            if (digest_files > 0)
            {
                std::cout << "Of those scanned, including " << digest_files
                    << " file";
                if (digest_files > 1)
                {
                    std::cout << 's';
                }
                std::cout << " with size <= " << MATCH_BYTES_X2 << " bytes."
                    << std::endl;
            }
        }

        num_size_db = candidates(size_db);
        if (!(options & QUIET))
        {
            std::cout << "After running stage 1 filter, " << num_size_db
                << " candidates remain.\n";
            std::cout << "This scan took " << sw.elapsedStr() << ".\n"
                << std::endl;
            sw.mark();
        }

        //--- STAGE 2 SCAN ----------------------------------------------------

        // find stage 2 duplicates - read top 64 bytes
        if (num_size_db > 0)
        {
            if (!(options & QUIET))
            {
                std::cout << "Running stage 2 filter; please wait..."
                    << std::endl;
            }

            scanTopBytes();
            num_top_db = candidates(top_db);
            if (!(options & QUIET) && (num_size_db > 0))
            {
                std::cout << "After running stage 2 filter, " << num_top_db
                    << " candidates remain." << std::endl;
            }
            std::cout << "This filter took " << sw.elapsedStr() << ".\n"
                << std::endl;
            sw.mark();
        }

        //--- STAGE 3 SCAN ----------------------------------------------------

        // find stage 3 duplicates - read bottom 64 bytes
        if (num_top_db > 0)
        {
            if (!(options & QUIET))
            {
                std::cout << "Running stage 3 filter; please wait..."
                    << std::endl;
            }

            scanBottomBytes();
            num_bottom_db = candidates(bottom_db);
            if (!(options & QUIET) && (num_top_db > 0))
            {
                std::cout << "After running stage 3 filter, " << num_bottom_db
                    << " candidates remain." << std::endl;
            }
            std::cout << "This filter took " << sw.elapsedStr() << ".\n"
                << std::endl;
            sw.mark();
        }

        //--- STAGE 4 SCAN ----------------------------------------------------
        if (!(options & QUIET))
        {
            std::cout << "Running stage 4 filter; please wait..." << std::endl;
        }

        // find stage 4 duplicates - perform DIGEST on remaining file
        // candidates
        for (auto p = bottom_db.begin(); p != bottom_db.end(); ++p)
        {
            // convenience aliases
            SizeChecksum const &key = p->first;
            IndexList const &indices = p->second;
            size_t const &size = key.first;

            // perform digest on each file
            for (auto q = p->second.begin(); q != p->second.end(); ++q)
            {
                auto index = *q;
                std::string const &file = path_list[index];
                performDigest(file.c_str(), size, index);
            }
        }

        size_t num_digest_db = candidates(digest_db);
        if (!(options & QUIET))
        {
            if (num_bottom_db > 0)
            {
                std::cout << "After running stage 4 filter, "
                    << num_digest_db << " candidates remain.\n" << std::endl;
            }

            std::cout << "This filter took " << sw.elapsedStr() << std::endl;
            sw.mark();

            double duplicate_percent = (num_digest_db * 100.0f) / total_files;
            std::cout << std::setprecision(4) << duplicate_percent
                << "% of scanned files are duplicate.\n" << std::endl;
        }

        //--- FINISHED; DISPLAY RESULTS ---------------------------------------

        // Display duplicate files
        size_t dup_set = 1;
        for (auto p = digest_db.begin(); p != digest_db.end(); ++p)
        {
            // convenience aliases
            IndexList const &indices = p->second;
            size_t num_indices = indices.size();

            // only print duplicates
            if (num_indices > 1)
            {
                std::cout << "Set " << dup_set++ << " has " << num_indices
                    << " duplicate files." << std::endl;

                // iterate through each file with same digest
                for (auto q = p->second.begin(); q != p->second.end(); ++q)
                {
                    auto index = *q;
                    std::string const &file = path_list[index];

                    std::cout << file << std::endl;
                }
            }
        }
    }

    return result;
}

/*-----------------------------------------------------------------------------
 *  main entry point
 *
 *-----------------------------------------------------------------------------
 */
int main(int argc, char *argv[])
{
    int result = EXIT_FAILURE;

    Stopwatch sw;

    // no arguments not allowed, must at least specify PATH argument
    if (1 == argc)
    {
        std::cout << usage << std::endl;
    }
    else if (true == processArguments(argc, argv))
    {
        char const *path = argv[optind];
        if (NULL == path)
        {
            std::cout << "PATH argument is required.\n";
        }
        else
        {
            // start the search for duplicates
            result = search(path);
        }
    }

    if (result != EXIT_FAILURE)
    {
        std::cout << "This scan took " << sw.elapsedStr() << ".\n"
            << std::endl;
    }

    return result;
}
