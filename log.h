#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#ifndef NDEBUG
#define LOG_DEBUG(format, ...)                                                            \
    do                                                                                    \
    {                                                                                     \
        printf("DEBUG: File:%s, Line:%d, " format "", __FILE__, __LINE__, ##__VA_ARGS__); \
                                                                                          \
    } while (0)
#else
#define LOG_DEBUG(format, ...)
#endif

#define LOG_INFO(format, ...)                                                             \
    do                                                                                    \
    {                                                                                     \
        printf("INFO:  File:%s, Line:%d, " format "", __FILE__, __LINE__, ##__VA_ARGS__); \
                                                                                          \
    } while (0)

#endif
