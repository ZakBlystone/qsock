//Quick socket header-only library
//Platform-agnostic thin c++ library on top of socket functions to make my life easier
//Uses RAII for all types for easy peasy use.

//Define QSOCK_IMPLEMENTATION in one CPP file

//By Zachary Blystone (2017)
//Public-domain

#ifndef QSOCK_H_INCLUDE
#define QSOCK_H_INCLUDE

#include <string>
#include <memory>
#include <string.h>

#ifdef _WIN32
	#ifndef _WIN32_WINNT
	#define _WIN32_WINNT 0x0501
	#endif
	#include <winsock2.h>
	#include <Ws2tcpip.h>
	#pragma comment(lib, "wsock32.lib")
	#pragma warning( disable : 4290 )  	

	#define IP(addr) (addr).S_un.S_addr

#else
	#include <sys/socket.h>
	#include <arpa/inet.h>
	#include <netdb.h>
	#include <unistd.h>
	#include <fcntl.h>

	#define SOCKET int
	#define SOCKET_ERROR -1
	#define INVALID_SOCKET -1

	#define IP(addr) (addr).s_addr
#endif

typedef std::shared_ptr<class TCPSocket> TCPSocketPtr;

#ifdef QSOCK_IMPLEMENTATION
static void endpointToSockAddr(const class Endpoint& e, sockaddr_in& in, int& len);
static void endpointFromSockAddr(class Endpoint& e, sockaddr_in& in);
#endif

struct SocketException
{
	SocketException(std::string message, int errorno);
	std::string getMessage();
	std::string getError();
	int getErrorno();
private:
	std::string _message;
	std::string _error;
	int _errorno;
};

class IPAddress
{
public:
	IPAddress();
	IPAddress(const std::string& address);
	std::string getString() const;

	unsigned long getAddr() const;
	bool isValid() const;
private:
	IPAddress(unsigned long l);

	friend class Host;
	friend class UDPSocket;
	friend class TCPSocket;

#ifdef QSOCK_IMPLEMENTATION
	friend void endpointToSockAddr(const class Endpoint& e, sockaddr_in& in, int& len);
	friend void endpointFromSockAddr(class Endpoint& e, sockaddr_in& in);
#endif
	
	unsigned long _address;
};

class Endpoint
{
public:
	IPAddress address;
	unsigned short port;
};

class Host
{
public:
	Host(const std::string& name) throw(SocketException);

	IPAddress getIP() const;
	Endpoint getEndpoint(short port) const;
private:
	IPAddress _ip;
};

class UDPSocket
{
public:
	UDPSocket() throw(SocketException);
	~UDPSocket();

	void bind(short port) throw (SocketException);
	void bind(IPAddress ipaddress, short port) throw (SocketException);
	void bind(Endpoint &endpoint) throw (SocketException);
	int sendTo(const char *buffer, int buflen, const Endpoint &endpoint) throw (SocketException);
	int recvFrom(char *buffer, int buflen, Endpoint &endpoint) throw (SocketException);
private:
	SOCKET _sock;
	IPAddress _ip;
	unsigned short _port;
};

class TCPSocket
{
public:
	TCPSocket() throw(SocketException);
	~TCPSocket();

	bool setTimeout(int ms);
	void bind(short port) throw (SocketException);
	void bind(IPAddress ipaddress, short port) throw (SocketException);
	void connect(IPAddress ipaddress, short port) throw (SocketException);
	void listen(int backlog) throw (SocketException);
	TCPSocketPtr accept(Endpoint &endpoint) throw (SocketException);
	int send(const char *buffer, unsigned buflen) throw (SocketException);
	int recv(char *buffer, unsigned buflen) throw (SocketException);
	void setNonBlocking(bool nonblocking) throw (SocketException);
	bool isNonBlocking() const;
private:
	TCPSocket(SOCKET sock, IPAddress ip, short port);
	SOCKET _sock;
	IPAddress _ip;
	unsigned short _port;
	bool _nonblocking;
};

#ifdef QSOCK_IMPLEMENTATION

//Exceptions

static std::string getErrorString(int errorno)
{
#ifdef _WIN32
	char *s = NULL;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
	               NULL, errorno,
	               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	               (LPSTR)&s, 0, NULL);
	std::string messageStr(s);
	LocalFree(s);

	return messageStr;
#else
	return std::string(strerror(errorno));
#endif
}

std::string SocketException::getMessage() {return _message;}
std::string SocketException::getError() {return _error; }
int SocketException::getErrorno() {return _errorno; }

SocketException::SocketException(std::string message, int errorno) 
	: _message(message)
	, _errorno(errorno)
{
	_error = getErrorString(_errorno);
}

//IP Address

IPAddress::IPAddress() 
	: _address(INADDR_ANY) 
{}

IPAddress::IPAddress(const std::string& address) 
	: _address( inet_addr(address.c_str()) )
{}

IPAddress::IPAddress(unsigned long l) 
	: _address(l) 
{}

std::string IPAddress::getString() const
{
	return std::string( inet_ntoa( *(in_addr*) &_address ) ); 
}

unsigned long IPAddress::getAddr() const { return _address; }
bool IPAddress::isValid() const { return _address != INADDR_NONE; }

//Endpoint

static void endpointToSockAddr(const Endpoint& e, sockaddr_in& in, int& len)
{
	in.sin_port = htons(e.port);
	in.sin_family = AF_INET;
	IP(in.sin_addr) = e.address.getAddr();
	len = sizeof(sockaddr_in);
}

static void endpointFromSockAddr(Endpoint& e, sockaddr_in& in)
{
	e.address = IPAddress(IP(in.sin_addr));
	e.port = ntohs(in.sin_port);
}

static int getError()
{
#ifdef _WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

static inline bool isError(int errorno)
{
#ifdef _WIN32
	return errorno != EXIT_SUCCESS;
#else
	return errorno != EXIT_SUCCESS;
#endif
}

static inline bool wouldblock(int errorno)
{
#ifdef _WIN32
	return errorno == WSAEWOULDBLOCK;
#else
	return errorno == EWOULDBLOCK;
#endif
}

//Host

Host::Host(const std::string& name) throw (SocketException)
{
	hostent *host = gethostbyname(name.c_str());
	if ( host == NULL ) throw SocketException("Failed to find host", getError());

	in_addr *addr = (in_addr*)*host->h_addr_list;
	_ip = IPAddress(IP(*addr));
}

IPAddress Host::getIP() const
{
	return _ip;
}

Endpoint Host::getEndpoint(short port) const
{
	Endpoint e;
	e.address = _ip;
	e.port = port;
	return e;
}

//UDP Socket

UDPSocket::UDPSocket() throw (SocketException)
{
	_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( _sock == INVALID_SOCKET )
	{
		throw SocketException("Failed to create UDP socket", getError());
	}

#ifdef _WIN32
	unsigned long mode = 1;
	if(ioctlsocket(_sock, FIONBIO, &mode))
	{
		throw SocketException("setNonBlocking failed on TCP socket", getError());
	}
#else
	int flags = fcntl(_sock, F_GETFL, 0) | O_NONBLOCK;
	if ( fcntl(_sock, F_SETFL, flags) != 0 )
	{
		throw SocketException("setNonBlocking failed on TCP socket", getError());
	}
#endif
}

UDPSocket::~UDPSocket()
{
	int status = 0;
#ifdef _WIN32
	status = shutdown(_sock, SD_BOTH);
	if ( status == 0 ) status = closesocket(_sock);
#else
	status = shutdown(_sock, SHUT_RDWR);
	if ( status == 0 ) status = close(_sock);
#endif
}

void UDPSocket::bind(short port) throw (SocketException)
{
	bind(INADDR_ANY, port);
}

void UDPSocket::bind(IPAddress ipaddress, short port) throw (SocketException)
{
	sockaddr_in address;
	int result;
	address.sin_port = htons(port);
	address.sin_family = AF_INET;
	IP(address.sin_addr) = ipaddress.getAddr();
	_ip = ipaddress;
	_port = port;
	result = ::bind(_sock, (sockaddr*)&address, sizeof(address));

	if (result == SOCKET_ERROR)
	{
		throw SocketException("bind failed on UDP socket", getError());
	}
}

void UDPSocket::bind(Endpoint &endpoint) throw (SocketException)
{
	bind(endpoint.address, endpoint.port);
}

int UDPSocket::sendTo(const char *buffer, int buflen, const Endpoint &endpoint) throw (SocketException)
{
	int len;
	sockaddr_in to;
	endpointToSockAddr(endpoint, to, len);
	int result = ::sendto(_sock, buffer, buflen, 0, (sockaddr*)&to, len);
	if(result == SOCKET_ERROR)
	{
		int errorno = getError();
		if( isError(errorno) && !wouldblock(errorno) )
		{
			throw SocketException("sendTo failed on UDP socket", errorno);
		}
	}
	return result;
}

int UDPSocket::recvFrom(char *buffer, int buflen, Endpoint &endpoint) throw (SocketException)
{
	socklen_t fromlen = sizeof(sockaddr_in);
	sockaddr_in from;

	memset(&from, 0, sizeof(from));

	int result = ::recvfrom(_sock, buffer, buflen, 0, (sockaddr*)&from, &fromlen);
	endpointFromSockAddr(endpoint, from);

	if(result == SOCKET_ERROR)
	{
		int errorno = getError();
		if( isError(errorno) && !wouldblock(errorno) )
		{
			throw SocketException("recvFrom failed on UDP socket", errorno);
		}
		return -1;
	}
	return result;
}

//TCPSocket

TCPSocket::TCPSocket() throw (SocketException)
{
	_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if( _sock == INVALID_SOCKET )
	{
		throw SocketException("Failed to create TCP socket", getError());
	}
	_nonblocking = false;
}

TCPSocket::~TCPSocket()
{
	int status = 0;
#ifdef _WIN32
	status = shutdown(_sock, SD_BOTH);
	if ( status == 0 ) status = closesocket(_sock);
#else
	status = shutdown(_sock, SHUT_RDWR);
	if ( status == 0 ) status = close(_sock);
#endif
}

TCPSocket::TCPSocket(SOCKET sock, IPAddress ip, short port) 
	: _sock(sock)
	, _ip(ip)
	, _port(port) 
{}

bool TCPSocket::setTimeout(int ms)
{
	if(setsockopt(_sock,SOL_SOCKET,SO_RCVTIMEO,(const char *)&ms,sizeof(ms)))
	{
		return false;
	}
	return true;
}

void TCPSocket::bind(short port) throw (SocketException)
{
	bind(INADDR_ANY, port);
}

void TCPSocket::bind(IPAddress ipaddress, short port) throw (SocketException)
{
	sockaddr_in address;
	int result;
	address.sin_port = htons(port);
	address.sin_family = AF_INET;
	IP(address.sin_addr) = ipaddress.getAddr();
	_ip = ipaddress;
	_port = port;
	result = ::bind(_sock, (sockaddr*)&address, sizeof(address));
	if (result == SOCKET_ERROR)
	{
		throw SocketException("bind failed on TCP socket", getError());
	}
}

void TCPSocket::connect(IPAddress ipaddress, short port) throw (SocketException)
{
	sockaddr_in address;
	address.sin_port = htons(port);
	address.sin_family = AF_INET;
	IP(address.sin_addr) = ipaddress.getAddr();
	int result = ::connect(_sock, (sockaddr*) &address, sizeof(sockaddr_in));
	if (result == SOCKET_ERROR)
	{
		throw SocketException("connect failed on TCP socket", getError());
	}
}

void TCPSocket::listen(int backlog) throw (SocketException)
{
	int result = ::listen(_sock, backlog);
	if (result == SOCKET_ERROR)
	{
		throw SocketException("listen failed on TCP socket", getError());
	}
}

TCPSocketPtr TCPSocket::accept(Endpoint &endpoint) throw (SocketException)
{
	sockaddr_in addr;
	socklen_t addrlen = sizeof(sockaddr_in);
	SOCKET s = ::accept(_sock, (sockaddr*) &addr, &addrlen);
	if(s == INVALID_SOCKET)
	{
		int errorno = getError();
		if( isError(errorno) && !wouldblock(errorno) )
		{
			throw SocketException("accept failed on TCP socket", errorno);
		}
		else
		{
			return NULL;
		}
	}
	endpoint.address = IPAddress(IP(addr.sin_addr));
	endpoint.port = ntohs(addr.sin_port);
	return std::shared_ptr<TCPSocket>( new TCPSocket(s, endpoint.address, endpoint.port) );
}

int TCPSocket::send(const char *buffer, unsigned buflen) throw (SocketException)
{
	int result = ::send(_sock, const_cast<char*>(buffer), buflen, 0);

	if ( result == SOCKET_ERROR )
	{
		int errorno = getError();
		if( isError(errorno) && !wouldblock(errorno) )
		{
			throw SocketException("send failed on TCP socket", errorno);
		}
	}

	return result;
}

int TCPSocket::recv(char *buffer, unsigned buflen) throw (SocketException)
{
	int result = ::recv(_sock, buffer, buflen, 0);
	if(!_nonblocking)
	{
		if(result == SOCKET_ERROR)
		{
			int errorno = getError();
			if ( isError(errorno) )
			{
				throw SocketException("recv failed on TCP socket", errorno);
			}
		}
	}
	else
	{
		if(result == SOCKET_ERROR)
		{
			int errorno = getError();
			if( !wouldblock(errorno) )
			{
				throw SocketException("recv failed on non-blocking TCP socket", errorno);
			}
			return -1;
		}
	}
	return result;
}

void TCPSocket::setNonBlocking(bool nonblocking) throw (SocketException)
{
#ifdef _WIN32
	unsigned long mode = nonblocking ? 1 : 0;
	if(ioctlsocket(_sock, FIONBIO, &mode))
	{
		throw SocketException("setNonBlocking failed on TCP socket", getError());
	}
#else
	int flags = fcntl(_sock, F_GETFL, 0);
	if ( flags < 0 ) return;
	if ( nonblocking ) flags |= O_NONBLOCK;
	else flags &= ~O_NONBLOCK;

	if ( fcntl(_sock, F_SETFL, flags) != 0 )
	{
		throw SocketException("setNonBlocking failed on TCP socket", getError());
	}
#endif
	_nonblocking = nonblocking;
}

bool TCPSocket::isNonBlocking() const
{
	return _nonblocking;
}

//Environment

struct SockEnv
{
	SockEnv()
	{
#ifdef _WIN32
		WSADATA wsa_data;
		status = WSAStartup(MAKEWORD(1,1), &wsa_data);
#else
		status = 0;
#endif	
	}

	~SockEnv()
	{
#ifdef _WIN32
		WSACleanup();
#endif
	}

private:
	int status;
};

static SockEnv __sockenv;

//QSOCK_IMPLEMENTATION
#endif

//QSOCK_H_INCLUDE
#endif
