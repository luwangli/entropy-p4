#include <string>
#include <iostream>
#include <netinet/ip.h>

int main()
{
    std::cout<<"16to10: "<<ntohl(0x700)<<std::endl;
    std::cout<<"16to10: "<<ntohl(1600)<<std::endl;
    std::cout<<"16to10: "<<ntohl(700)<<std::endl;

//    printf("%d \n",ntohl(0x700));
}

