#ifndef _H_TCPDAEMON_IN_
#define _H_TCPDAEMON_IN_

/*
 * tcpdaemon - TCP���ӹ����ػ�
 * author      : calvin
 * email       : calvinwilliams@163.com
 *
 * Licensed under the LGPL v2.1, see the file LICENSE in base directory.
 */

#include "LOGC.h"

#include "tcpdaemon.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IOMP */
#define MAX_IOMP_EVENTS			1024

/* �ź���ֵ�ṹ */
union semun
{
	int		val ;
	struct semid_ds	*buf ;
	unsigned short	*array ;
	struct seminfo	*__buf ;
};

/* �ػ������ṹ */
typedef struct
{
	int		fd[ 2 ] ;
} PIPE_T ;

struct TcpdaemonServerEnvirment
{
	struct TcpdaemonEntryParameter	*p_para ;
	
	OBJECTHANDLE			so_handle ; /* ��̬��򿪾�� */
	func_tcpmain			*pfunc_tcpmain ; /* ��̬�����:ͨѶ����Э�鼰Ӧ�ô���ص����� */
	void				*param_tcpmain ; /* ��ڲ��� */
	int				listen_sock ; /* �����׽��� */
	struct sockaddr_in		listen_addr ; /* ���������ַ */
	
	PID_T				*pids ;
	PIPE_T				*alive_pipes ; /* �������̻�֪������̻��ܵ�������˵�ǹ������֪ͨ�������̽���������ܵ� */
					/* parent fd[1] -> child fd[0] */
	
	/* ��Instance-Fork����ģ��ʹ�� */
	int				process_count ;
	
	/* ��Leader-Follow���̳�ģ��ʹ�� */
	int				accept_mutex ; /* accept�ٽ��� */
	int				index ; /* ����������� */
	int				requests_per_process ; /* �������̵�ǰ�������� */
	
	/* ��MultiplexIO���̳�ģ��ʹ�� */
	int				*epoll_array ;
	unsigned char			io_multiplex_event ;
	
	/* ��Leader-Follow�̳߳�ģ��ʹ�� */
	THANDLE_T			*thandles ;
	TID_T				*tids ;
} ;

#ifdef __cplusplus
}
#endif

#endif

