%module pcapgen

%include <typemaps.i>
%include <std_pair.i>
%include <std_string.i>
%include "exception.i"


%{
#include "pcapgen.h"
%}


class TcpSocket
{
public:
    void close();
    void send(const std::string&);
};


%template(TcpSocketPair) std::pair<TcpSocket, TcpSocket>;


%exception create_connection {
    try {
        $action
    } catch (std::runtime_error& e) {
        SWIG_exception(SWIG_RuntimeError,const_cast<char*>(e.what()));
    }
}


class PcapGen
{
public:
    void close();
    std::pair<TcpSocket, TcpSocket>
    create_connection(const std::string& client_addr,
                      const std::string& server_addr);
};


namespace std {

template<class T> class shared_ptr
{
public:
    T* operator -> ();
};

}


%template(PcapGenPtr) std::shared_ptr<PcapGen>;


%exception open {
    try {
        $action
    } catch (std::runtime_error& e) {
        SWIG_exception(SWIG_RuntimeError,const_cast<char*>(e.what()));
    }
}


std::shared_ptr<PcapGen> open(const std::string& path);

