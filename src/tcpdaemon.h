#ifndef _H_TCPDAEMON_
#define _H_TCPDAEMON_

/*
 * tcpdaemon - TCP���ӹ����ػ�
 * author      : calvin
 * email       : calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#if ( defined __linux__ ) || ( defined __unix )
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utmpx.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#elif ( defined _WIN32 )
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <direct.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WINDLL_FUNC
#if ( defined __unix ) || ( defined __linux__ )
#define _WINDLL_FUNC
#elif ( defined _WIN32 )
#define _WINDLL_FUNC		_declspec(dllexport)
#endif
#endif

/* ������ */
#ifndef STRCMP
#define STRCMP(_a_,_C_,_b_) ( strcmp(_a_,_b_) _C_ 0 )
#define STRNCMP(_a_,_C_,_b_,_n_) ( strncmp(_a_,_b_,_n_) _C_ 0 )
#endif

#ifndef MEMCMP
#define MEMCMP(_a_,_C_,_b_,_n_) ( memcmp(_a_,_b_,_n_) _C_ 0 )
#endif

/* ��ƽ̨�� */
#if ( defined __linux__ ) || ( defined __unix )
#define RECV			recv
#define SEND			send
#elif ( defined _WIN32 )
#define RECV			recv
#define SEND			send
#endif

/* ��ƽ̨�� */
#if ( defined __linux__ ) || ( defined __unix )
#define PID_T			pid_t
#define TID_T			pthread_t
#define THANDLE_T		pthread_t
#define OBJECTHANDLE		void *
#define ERRNO			errno
#define DLERROR			dlerror()
#define OPEN			open
#define CLOSE			close
#define CLOSESOCKET		close
#define VSNPRINTF		vsnprintf
#define SNPRINTF		snprintf
#define SOCKLEN_T		socklen_t
#define PIPE(_pipes_)		pipe(_pipes_)
#define SLEEP(_seconds_)	sleep(_seconds_)
#define CHDIR			chdir
#elif ( defined _WIN32 )
#define PID_T			long
#define TID_T			unsigned long
#define THANDLE_T		HANDLE
#define OBJECTHANDLE		HINSTANCE
#define ERRNO			GetLastError()
#define DLERROR			""
#define OPEN			_open
#define CLOSE			_close
#define CLOSESOCKET		closesocket
#define VSNPRINTF		_vsnprintf
#define SNPRINTF		_snprintf
#define SOCKLEN_T		long
#define PIPE(_pipes_)		_pipe((_pipes_),256,_O_BINARY)
#define SLEEP(_seconds_)	Sleep(_seconds_*1000)
#define CHDIR			_chdir
#endif

/* ��־�ȼ� */
#ifndef LOGLEVEL_DEBUG
#define LOGLEVEL_DEBUG		1
#define LOGLEVEL_INFO		2
#define LOGLEVEL_WARN		3
#define LOGLEVEL_ERROR		4
#define LOGLEVEL_FATAL		5
#endif

/* �汾���ַ��� */
extern char		*__TCPDAEMON_VERSION ;

/*
 * ͨѶ��
 */

/* ���ػ�ģʽ : tcpdaemon(main->tcpdaemon->tcpmain) + xxx.so(tcpmain) */

#define TCPMAIN		"tcpmain"

/* ��������ģʽ : xxx.exe(main) + tcpdaemon.so(tcpdaemon) + xxx.exe(tcpmain) */

/* ͨѶ����Э�鼰Ӧ�ô���ص�����ԭ�� */
struct TcpdaemonEntryParameter ;
struct TcpdaemonServerEnvironment ;

typedef int func_tcpdaemon( struct TcpdaemonEntryParameter *p_para );

typedef int func_tcpmain( struct TcpdaemonServerEnvironment *p_env , int sock , void *p_addr );
/* ����˵�� */
	/*
	IF
					p_env , int accepted_sock , struct sockaddr *accepted_addr
	LF
					p_env , int accepted_sock , struct sockaddr *accepted_addr
	IOMP
		OnAcceptingSocket	p_env , int accepted_sock , struct sockaddr *accepted_addr
		OnClosingSocket		p_env , 0 , void *custem_data_ptr
		OnSendingSocket		p_env , 0 , void *custem_data_ptr
		OnReceivingSocket	p_env , 0 , void *custem_data_ptr
		OnClosingSocket		p_env , 0 , void *custem_data_ptr
	WIN-TLF
					p_env , int accepted_sock , struct sockaddr *accepted_addr
	*/
/* ����ֵ˵�� */
#define TCPMAIN_RETURN_CLOSE			0
#define TCPMAIN_RETURN_WAITINGFOR_RECEIVING	1	
#define TCPMAIN_RETURN_WAITINGFOR_SENDING	2	
#define TCPMAIN_RETURN_WAITINGFOR_NEXT		3	
#define TCPMAIN_RETURN_ERROR			-1

/* ����ڲ����ṹ */
struct TcpdaemonEntryParameter
{
	int		daemon_level ;	/* �Ƿ�ת��Ϊ�ػ����� 1:ת�� 0:��ת����ȱʡ�� */
	
	char		log_pathfilename[ 256 + 1 ] ;	/* ��־����ļ��������������������׼����� */
	int		log_level ;	/* ��־�ȼ� */
	
	char		server_model[ 10 + 1 ] ;	/* TCP���ӹ���ģ��
							LF:�쵼��-׷����Ԥ�������̳�ģ�� for UNIX,Linux
							IF:��ʱ��������ģ�� for UNIX,Linux
							WIN-TLF:�쵼��-׷����Ԥ�����̳߳�ģ�� for win32
							*/
	int		process_count ;	/* ��Ϊ�쵼��-׷����Ԥ�������̳�ģ��ʱΪ�������̳ؽ�����������Ϊ��ʱ��������ģ��ʱΪ����ӽ�����������ΪIO��·����ģ��ʱΪ�������̳ؽ������� */
	int		max_requests_per_process ;	/* ��Ϊ�쵼��-׷����Ԥ�������̳�ģ��ʱΪ�����������������Ӧ�ô��� */
	char		ip[ 20 + 1 ] ;	/* ��������IP */
	int		port ;	/* ��������PORT */
	char		so_pathfilename[ 256 + 1 ] ;	/* �þ���·�������·������Ӧ�ö�̬���ļ��� */
	
	char		work_user[ 64 + 1 ] ;	/* �л�Ϊ�����û����С���ѡ */
	char		work_path[ 256 + 1 ] ;	/* �л���ָ��Ŀ¼���С���ѡ */
	
	func_tcpmain	*pfunc_tcpmain ;	/* ����������ģʽʱ��ָ���TCP���ӽ���Ӧ����ں���ָ�� */
	void		*param_tcpmain ;	/* ����������ģʽʱ��ָ���TCP���ӽ���Ӧ����ں����Ĳ���ָ�롣�ر�ע�⣺�Լ���֤�̰߳�ȫ */
	
	int		tcp_nodelay ;	/* ����TCP_NODELAYѡ�� 1:���� 0:�����ã�ȱʡ������ѡ */
	int		tcp_linger ;	/* ����TCP_LINGERѡ�� >=1:���ò����óɲ���ֵ 0:�����ã�ȱʡ������ѡ */
	
	int		timeout_seconds ; /* ��ʱʱ�䣬��λ���룻Ŀǰֻ��IO-Multiplexģ����Ч */
	int		cpu_affinity ; /* CPU��Ե�� */
	
	/* ����Ϊ�ڲ�ʹ�� */
	int		install_winservice ;
	int		uninstall_winservice ;
} ;

/* ����ں��� */
_WINDLL_FUNC int tcpdaemon( struct TcpdaemonEntryParameter *p_para );

/* WINDOWS������ */
#define TCPDAEMON_SERVICE		"TcpDaemon Service"

/* �����ṹ��Ա */
void *TDGetTcpmainParameter( struct TcpdaemonServerEnvironment *p_env );
int TDGetListenSocket( struct TcpdaemonServerEnvironment *p_env );
int *TDGetListenSocketPtr( struct TcpdaemonServerEnvironment *p_env );
struct sockaddr_in TDGetListenAddress( struct TcpdaemonServerEnvironment *p_env );
struct sockaddr_in *TDGetListenAddressPtr( struct TcpdaemonServerEnvironment *p_env );
int TDGetProcessCount( struct TcpdaemonServerEnvironment *p_env );
int *TDGetEpollArrayBase( struct TcpdaemonServerEnvironment *p_env );
int TDGetThisEpoll( struct TcpdaemonServerEnvironment *p_env );

#define IOMP_ON_ACCEPTING_SOCKET	1
#define IOMP_ON_CLOSING_SOCKET		2
#define IOMP_ON_RECEIVING_SOCKET	3
#define IOMP_ON_SENDING_SOCKET		4

int TDGetIoMultiplexEvent( struct TcpdaemonServerEnvironment *p_env );
void TDSetIoMultiplexDataPtr( struct TcpdaemonServerEnvironment *p_env , void *io_multiplex_data_ptr );

#ifdef __cplusplus
}
#endif

#endif

