#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>

#define PR_FMT     "session"
#define PR_DOMAIN  DBG_SESSION

#include "uftrace.h"
#include "utils/symbol.h"
#include "utils/rbtree.h"
#include "utils/utils.h"
#include "utils/fstack.h"
#include "libmcount/mcount.h"

static void delete_tasks(struct uftrace_session_link *sessions);

/**
 * read_session_map - read memory mappings in a session map file
 * @dirname: directory name of the session
 * @symtabs: symbol table to keep the memory mapping
 * @sid: session id
 *
 * This function reads mapping data from a session map file and
 * construct the address space for a session to resolve symbols
 * in libraries.
 */
void read_session_map(char *dirname, struct symtabs *symtabs, char *sid)
{
	FILE *fp;
	char buf[PATH_MAX];
	const char *last_libname = symtabs->filename;
	struct uftrace_mmap **maps = &symtabs->maps;

	snprintf(buf, sizeof(buf), "%s/sid-%.16s.map", dirname, sid);
	fp = fopen(buf, "rb");
	if (fp == NULL)
		pr_err("cannot open maps file: %s", buf);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		uint64_t start, end;
		char prot[5];
		char path[PATH_MAX];
		size_t namelen;
		struct uftrace_mmap *map;

		/* skip anon mappings */
		if (sscanf(buf, "%"PRIx64"-%"PRIx64" %s %*x %*x:%*x %*d %s\n",
			   &start, &end, prot, path) != 4)
			continue;

		/* skip the [stack] mapping */
		if (path[0] == '[') {
			if (strncmp(path, "[stack", 6) == 0)
				symtabs->kernel_base = guess_kernel_base(buf);
			continue;
		}

		/* use first mapping only (even if it's non-exec) */
		if (last_libname && !strcmp(last_libname, path)) {
			if (symtabs->filename && !strcmp(path, symtabs->filename)) {
				/* update it only once */
				if (symtabs->exec_base == 0)
					symtabs->exec_base = start;
			}
			continue;
		}

		namelen = ALIGN(strlen(path) + 1, 4);

		map = xzalloc(sizeof(*map) + namelen);

		map->start = start;
		map->end = end;
		map->len = namelen;

		memcpy(map->prot, prot, 4);
		memcpy(map->libname, path, namelen);
		map->libname[strlen(path)] = '\0';
		last_libname = map->libname;

		*maps = map;
		maps = &map->next;
	}
	fclose(fp);
}

/**
 * delete_session_map - free memory mappings in a symtabs
 * @symtabs: symbol table has the memory mapping
 *
 * This function releases mapping data in a symbol table which
 * was read by read_session_map().
 */
void delete_session_map(struct symtabs *symtabs)
{
	struct uftrace_mmap *map, *tmp;

	map = symtabs->maps;
	while (map) {
		tmp = map->next;
		unload_symtab(&map->symtab);
		free(map);
		map = tmp;
	}

	symtabs->maps = NULL;
}

/**
 * create_session - create a new task session from session message
 * @sessions: session link to manage sessions and tasks
 * @msg: uftrace session message read from task file
 * @dirname: uftrace data directory name
 * @exename: executable name started this session
 *
 * This function allocates a new session started by a task.  The new
 * session will be added to sessions tree sorted by pid and timestamp.
 */
void create_session(struct uftrace_session_link *sessions,
		    struct uftrace_msg_sess *msg, char *dirname, char *exename,
		    bool sym_rel_addr)
{
	struct uftrace_session *s;
	struct uftrace_task *t;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions->root.rb_node;

	while (*p) {
		parent = *p;
		s = rb_entry(parent, struct uftrace_session, node);

		if (s->pid > msg->task.pid)
			p = &parent->rb_left;
		else if (s->pid < msg->task.pid)
			p = &parent->rb_right;
		else if (s->start_time > msg->task.time)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}

	s = xzalloc(sizeof(*s) + msg->namelen + 1);

	memcpy(s->sid, msg->sid, sizeof(s->sid));
	s->start_time = msg->task.time;
	s->pid = msg->task.pid;
	s->tid = msg->task.tid;
	s->namelen = msg->namelen;
	memcpy(s->exename, exename, s->namelen);
	s->exename[s->namelen] = 0;
	s->filters = RB_ROOT;
	INIT_LIST_HEAD(&s->dlopen_libs);

	pr_dbg2("new session: pid = %d, session = %.16s\n",
		s->pid, s->sid);

	s->symtabs.filename = s->exename;
	s->symtabs.flags = SYMTAB_FL_USE_SYMFILE | SYMTAB_FL_DEMANGLE;
	if (sym_rel_addr)
		s->symtabs.flags |= SYMTAB_FL_ADJ_OFFSET;

	read_session_map(dirname, &s->symtabs, s->sid);
	load_symtabs(&s->symtabs, dirname, s->exename);

	load_module_symtabs(&s->symtabs);
	load_debug_info(&s->symtabs);

	if (sessions->first == NULL)
		sessions->first = s;

	t = find_task(sessions, s->tid);
	if (t) {
		strncpy(t->comm, basename(exename), sizeof(t->comm));
		t->comm[sizeof(t->comm) - 1] = '\0';
	}

	rb_link_node(&s->node, parent, p);
	rb_insert_color(&s->node, &sessions->root);
}

static struct uftrace_session *find_session(struct uftrace_session_link *sessions,
					    int pid, uint64_t timestamp)
{
	struct uftrace_session *iter;
	struct uftrace_session *s = NULL;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions->root.rb_node;

	while (*p) {
		parent = *p;
		iter = rb_entry(parent, struct uftrace_session, node);

		if (iter->pid > pid)
			p = &parent->rb_left;
		else if (iter->pid < pid)
			p = &parent->rb_right;
		else if (iter->start_time > timestamp)
			p = &parent->rb_left;
		else {
			s = iter;
			p = &parent->rb_right;
		}
	}

	return s;
}

/**
 * walk_sessions - iterates all session and invokes @callback
 * @sessions: session link to manage sessions and tasks
 * @callback: function to be called for each task
 * @arg: argument passed to the @callback
 *
 * This function traverses the task tree and invokes @callback with
 * @arg.  As the @callback returns a non-zero value, it'll stop and
 * return in the middle.
 */
void walk_sessions(struct uftrace_session_link *sessions,
		   walk_sessions_cb_t callback, void *arg)
{
	struct rb_node *n = rb_first(&sessions->root);
	struct uftrace_session *s;

	while (n) {
		s = rb_entry(n, struct uftrace_session, node);

		if (callback(s, arg) != 0)
			break;

		n = rb_next(n);
	}
}

/**
 * get_session_from_sid - find a session using @sid
 * @sessions: session link to manage sessions and tasks
 * @sid: session ID
 *
 * This function returns a matching session or %NULL.
 */
struct uftrace_session *
get_session_from_sid(struct uftrace_session_link *sessions, char sid[])
{
	struct rb_node *n = rb_first(&sessions->root);
	struct uftrace_session *s;

	while (n) {
		s = rb_entry(n, struct uftrace_session, node);

		if (memcmp(s->sid, sid, sizeof(s->sid)) == 0)
			return s;

		n = rb_next(n);
	}
	return NULL;
}

/**
 * session_add_dlopen - add dlopen'ed library to the mapping table
 * @sess: pointer to a current session
 * @timestamp: timestamp at the dlopen call
 * @base_addr: load address of text segment of the library
 * @libname: name of the librarry
 *
 * This functions adds the info of a library which was loaded by dlopen.
 * Instead of creating a new session, it just adds the library information
 * to the @sess.
 */
void session_add_dlopen(struct uftrace_session *sess, uint64_t timestamp,
			unsigned long base_addr, const char *libname)
{
	struct uftrace_dlopen_list *udl, *pos;

	udl = xmalloc(sizeof(*udl) + strlen(libname) + 1);
	udl->time = timestamp;
	udl->base = base_addr;
	strcpy(udl->name, libname);

	memset(&udl->symtabs, 0, sizeof(udl->symtabs));
	udl->symtabs.flags = SYMTAB_FL_DEMANGLE | SYMTAB_FL_USE_SYMFILE;
	udl->symtabs.kernel_base = sess->symtabs.kernel_base;
	udl->symtabs.dirname = sess->symtabs.dirname;

	load_dlopen_symtabs(&udl->symtabs, base_addr, libname);

	list_for_each_entry(pos, &sess->dlopen_libs, list) {
		if (pos->time > timestamp)
			break;
	}
	list_add_tail(&udl->list, &pos->list);
}

/**
 * session_find_dlsym - find symbol from dlopen'ed library
 * @sess: pointer to a current session
 * @timestamp: timestamp of the address
 * @addr: instruction address
 *
 * This functions find a matching symbol from a dlopen'ed library in
 * @sess using @addr.  The @timestamp is needed to determine which
 * library should be searched.
 */
struct sym * session_find_dlsym(struct uftrace_session *sess, uint64_t timestamp,
				unsigned long addr)
{
	struct uftrace_dlopen_list *pos;
	struct sym *sym;

	list_for_each_entry_reverse(pos, &sess->dlopen_libs, list) {
		if (pos->time > timestamp)
			continue;

		sym = find_symtabs(&pos->symtabs, addr);
		if (sym)
			return sym;
	}

	return NULL;
}

void delete_session(struct uftrace_session *sess)
{
	struct uftrace_dlopen_list *udl, *tmp;

	list_for_each_entry_safe(udl, tmp, &sess->dlopen_libs, list) {
		list_del(&udl->list);
		unload_symtabs(&udl->symtabs);
		free(udl);
	}

	finish_debug_info(&sess->symtabs);
	unload_symtabs(&sess->symtabs);
	delete_session_map(&sess->symtabs);
	uftrace_cleanup_filter(&sess->filters);
	uftrace_cleanup_filter(&sess->fixups);
	free(sess);
}

/**
 * delete_sessions - free all resouces in the @sessions
 * @sessions: session link to manage sessions and tasks
 *
 * This function removes all session-related data structure in
 * @sessions.
 */
void delete_sessions(struct uftrace_session_link *sessions)
{
	struct uftrace_session *sess;
	struct rb_node *n;

	delete_tasks(sessions);

	while (!RB_EMPTY_ROOT(&sessions->root)) {
		n = rb_first(&sessions->root);
		rb_erase(n, &sessions->root);

		sess = rb_entry(n, struct uftrace_session, node);
		delete_session(sess);
	}
}

static void add_session_ref(struct uftrace_task *task, struct uftrace_session *sess,
			    uint64_t timestamp)
{
	struct uftrace_sess_ref *sref = &task->sref;

	if (sess == NULL) {
		pr_dbg("task %d/%d has no session\n", task->tid, task->pid);
		return;
	}

	if (task->sref_last) {
		task->sref_last->next = sref = xmalloc(sizeof(*sref));
		task->sref_last->end = timestamp;
	}

	sref->next = NULL;
	sref->sess = sess;
	sref->start = timestamp;
	sref->end = -1ULL;

	pr_dbg2("task session: tid = %d, session = %.16s\n",
		task->tid, sess->sid);
	task->sref_last = sref;
}

/**
 * find_task_session - find a matching session using @pid and @timestamp
 * @sessions: session link to manage sessions and tasks
 * @task: task to search a session
 * @timestamp: timestamp of task
 *
 * This function searches the sessions tree using @task and @timestamp.
 * The most recent session that has a smaller than the @timestamp will
 * be returned.  If it didn't find a session tries to search sesssion
 * list of parent or thread-leader.
 */
struct uftrace_session *find_task_session(struct uftrace_session_link *sessions,
					  struct uftrace_task *task,
					  uint64_t timestamp)
{
	int parent_id;
	struct uftrace_sess_ref *ref;

	while (task != NULL) {
		ref = &task->sref;
		while (ref) {
			if (ref->start <= timestamp && timestamp < ref->end)
				return ref->sess;
			ref = ref->next;
		}

		/*
		 * if it cannot find its own session,
		 * inherit from parent or leader.
		 */
		parent_id = task->ppid ?: task->pid;
		if (parent_id == 0 || parent_id == task->tid)
			break;

		task = find_task(sessions, parent_id);
	}

	return NULL;
}

/**
 * create_task - create a new task from task message
 * @sessions: session link to manage sessions and tasks
 * @msg: ftrace task message read from task file
 * @fork: whether it's forked or not (i.e. thread)
 *
 * This function creates a new task from @msg and add it to task tree.
 * The newly created task will have a reference to a session if
 * @needs_session is %true.
 */
void create_task(struct uftrace_session_link *sessions,
		 struct uftrace_msg_task *msg, bool fork, bool needs_session)
{
	struct uftrace_task *t;
	struct uftrace_session *s;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions->tasks.rb_node;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct uftrace_task, node);

		if (t->tid > msg->tid)
			p = &parent->rb_left;
		else if (t->tid < msg->tid)
			p = &parent->rb_right;
		else {
			if (needs_session) {
				/* add new session */
				s = find_session(sessions, msg->pid, msg->time);
				if (s != NULL)
					add_session_ref(t, s, msg->time);
			}
			return;
		}
	}

	t = xzalloc(sizeof(*t));

	/* msg->pid is a parent pid if forked */
	t->pid = fork ? msg->tid : msg->pid;
	t->tid = msg->tid;
	t->ppid = fork ? msg->pid : 0;

	if (needs_session) {
		s = find_session(sessions, msg->pid, msg->time);
		if (s == NULL) {
			struct uftrace_task *parent;

			parent = find_task(sessions, msg->pid);
			if (parent && parent->sref_last &&
			    parent->sref_last->start < msg->time)
				s = parent->sref_last->sess;
		}

		if (s) {
			add_session_ref(t, s, msg->time);
			strncpy(t->comm, basename(s->exename), sizeof(t->comm));
			t->comm[sizeof(t->comm) - 1] = '\0';
		}

		pr_dbg2("new task: tid = %d (%.*s), session = %-.16s\n",
			t->tid, sizeof(t->comm), s ? t->comm : "unknown",
			s ? s->sid : "unknown");
	}
	else {
		memset(&t->sref, 0, sizeof(t->sref));
		pr_dbg2("new task: tid = %d\n", t->tid);
	}

	rb_link_node(&t->node, parent, p);
	rb_insert_color(&t->node, &sessions->tasks);
}

static void delete_task(struct uftrace_task *t)
{
	struct uftrace_sess_ref *sref, *tmp;

	sref = t->sref.next;
	while (sref) {
		tmp = sref->next;
		free(sref);
		sref = tmp;
	}
	free(t);
}

static void delete_tasks(struct uftrace_session_link *sessions)
{
	struct uftrace_task *t;
	struct rb_node *n;

	while (!RB_EMPTY_ROOT(&sessions->tasks)) {
		n = rb_first(&sessions->tasks);
		rb_erase(n, &sessions->tasks);

		t = rb_entry(n, struct uftrace_task, node);
		delete_task(t);
	}
}

/**
 * find_task - find a matching task by @tid
 * @sessions: session link to manage sessions and tasks
 * @tid: task id
 */
struct uftrace_task *find_task(struct uftrace_session_link *sessions, int tid)
{
	struct uftrace_task *t;
	struct rb_node *parent = NULL;
	struct rb_node **p = &sessions->tasks.rb_node;

	while (*p) {
		parent = *p;
		t = rb_entry(parent, struct uftrace_task, node);

		if (t->tid > tid)
			p = &parent->rb_left;
		else if (t->tid < tid)
			p = &parent->rb_right;
		else
			return t;
	}

	return NULL;
}

/**
 * walk_tasks - iterates all tasks and invokes @callback
 * @sess: session link to manage sessions and tasks
 * @callback: function to be called for each task
 * @arg: argument passed to the @callback
 *
 * This function traverses the task tree and invokes @callback with
 * @arg.  As the @callback returns a non-zero value, it'll stop and
 * return in the middle.
 */
void walk_tasks(struct uftrace_session_link *sessions,
		walk_tasks_cb_t callback, void *arg)
{
	struct rb_node *n = rb_first(&sessions->tasks);
	struct uftrace_task *t;

	while (n) {
		t = rb_entry(n, struct uftrace_task, node);

		if (callback(t, arg) != 0)
			break;

		n = rb_next(n);
	}
}

/**
 * task_find_sym - find a symbol that matches to @rec
 * @sessions: session link to manage sessions and tasks
 * @task: handle for functions in a task
 * @rec: uftrace data record
 *
 * This function looks up symbol table in current session.
 */
struct sym * task_find_sym(struct uftrace_session_link *sessions,
			   struct uftrace_task_reader *task,
			   struct uftrace_record *rec)
{
	struct uftrace_session *sess;
	struct symtabs *symtabs;
	struct sym *sym = NULL;
	uint64_t addr = rec->addr;

	sess = find_task_session(sessions, task->t, rec->time);

	if (is_kernel_record(task, rec)) {
		if (sess == NULL)
			sess = sessions->first;
		addr = get_kernel_address(&sess->symtabs, addr);
	}

	if (sess == NULL)
		return NULL;

	symtabs = &sess->symtabs;
	sym = find_symtabs(symtabs, addr);

	if (sym == NULL)
		sym = session_find_dlsym(sess, rec->time, addr);

	return sym;
}

/**
 * task_find_sym - find a symbol that matches to @addr
 * @sessions: session link to manage sessions and tasks
 * @task: handle for functions in a task
 * @time: timestamp of the @addr
 * @addr: instruction address
 *
 * This function looks up symbol table in current session.
 */
struct sym * task_find_sym_addr(struct uftrace_session_link *sessions,
				struct uftrace_task_reader *task,
				uint64_t time, uint64_t addr)
{
	struct uftrace_session *sess;
	struct sym *sym = NULL;

	sess = find_task_session(sessions, task->t, time);

	if (sess == NULL) {
		struct uftrace_session *fsess = sessions->first;

		if (is_kernel_address(&fsess->symtabs, addr))
			sess = fsess;
		else
			return NULL;
	}

	sym = find_symtabs(&sess->symtabs, addr);
	if (sym == NULL)
		sym = session_find_dlsym(sess, time, addr);

	return sym;
}

#ifdef UNIT_TEST

static struct uftrace_session_link test_sessions;
static const char session_map[] =
	"00400000-00401000 r-xp 00000000 08:03 4096 unittest\n"
	"bfff0000-bffff000 rw-p 00000000 08:03 4096 [stack]\n";

TEST_CASE(session_search)
{
	int i;
	const int NUM_TEST = 100;

	TEST_EQ(test_sessions.first, NULL);

	for (i = 0; i < NUM_TEST; i++) {
		struct uftrace_msg_sess msg = {
			.task = {
				.pid = 1,
				.tid = 1,
				.time = i * 100,
			},
			.sid = "test",
			.namelen = 8,  /* = strlen("unittest") */
		};
		int fd;

		fd = creat("sid-test.map", 0400);
		write_all(fd, session_map, sizeof(session_map)-1);
		close(fd);
		create_session(&test_sessions, &msg, ".", "unittest", false);
		remove("sid-test.map");
	}

	TEST_NE(test_sessions.first, NULL);
	TEST_EQ(test_sessions.first->pid, 1);
	TEST_EQ(test_sessions.first->start_time, 0);

	for (i = 0; i < NUM_TEST; i++) {
		int t;
		struct uftrace_session *s;

		t = random() % (NUM_TEST * 100);
		s = find_session(&test_sessions, 1, t);

		TEST_NE(s, NULL);
		TEST_EQ(s->pid, 1);
		TEST_GE(t, s->start_time);
		TEST_LT(t, s->start_time + 100);
	}

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);

	return TEST_OK;
}

TEST_CASE(task_search)
{
	struct uftrace_task *task;
	struct uftrace_session *sess;
	int fd;

	/* 1. create initial task */
	{
		struct uftrace_msg_sess smsg = {
			.task = {
				.pid = 1,
				.tid = 1,
				.time = 100,
			},
			.sid = "initial",
			.namelen = 8,  /* = strlen("unittest") */
		};
		struct uftrace_msg_task tmsg = {
			.pid = 1,
			.tid = 1,
			.time = 100,
		};

		fd = creat("sid-initial.map", 0400);
		write_all(fd, session_map, sizeof(session_map)-1);
		close(fd);
		create_session(&test_sessions, &smsg, ".", "unittest", false);
		create_task(&test_sessions, &tmsg, false, true);
		remove("sid-initial.map");

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sref.sess, test_sessions.first);
		TEST_NE(test_sessions.first, NULL);

		sess = find_session(&test_sessions, tmsg.pid, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, task->pid);
		TEST_EQ(sess->tid, task->tid);
	}

	/* 2. fork child task */
	{
		struct uftrace_msg_task tmsg = {
			.pid = 1,  /* ppid */
			.tid = 2,  /* pid */
			.time = 200,
		};

		create_task(&test_sessions, &tmsg, true, true);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sref.sess, test_sessions.first);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 3. create parent thread */
	{
		struct uftrace_msg_task tmsg = {
			.pid = 1,
			.tid = 3,
			.time = 300,
		};

		create_task(&test_sessions, &tmsg, false, true);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sref.sess, test_sessions.first);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 4. create child thread */
	{
		struct uftrace_msg_task tmsg = {
			.pid = 2,
			.tid = 4,
			.time = 400,
		};

		create_task(&test_sessions, &tmsg, false, true);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);
		TEST_EQ(task->sref.sess, test_sessions.first);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		/* it returned a session from parent so pid is not same */
		TEST_NE(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 5. exec from child */
	{
		struct uftrace_msg_sess smsg = {
			.task = {
				.pid = 2,
				.tid = 4,
				.time = 500,
			},
			.sid = "after_exec",
			.namelen = 8,  /* = strlen("unittest") */
		};
		struct uftrace_msg_task tmsg = {
			.pid = 2,
			.tid = 4,
			.time = 500,
		};

		fd = creat("sid-after_exec.map", 0400);
		write_all(fd, session_map, sizeof(session_map)-1);
		close(fd);
		create_session(&test_sessions, &smsg, ".", "unittest", false);
		create_task(&test_sessions, &tmsg, false, true);
		remove("sid-after_exec.map");

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->pid, task->pid);
		TEST_EQ(sess->tid, task->tid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 6. fork grand-child task */
	{
		struct uftrace_msg_task tmsg = {
			.pid = 4,  /* ppid */
			.tid = 5,  /* pid */
			.time = 600,
		};

		create_task(&test_sessions, &tmsg, true, true);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		TEST_EQ(sess->tid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	/* 7. create grand-child thread */
	{
		struct uftrace_msg_task tmsg = {
			.pid = 5,
			.tid = 6,
			.time = 700,
		};

		create_task(&test_sessions, &tmsg, false, true);

		task = find_task(&test_sessions, tmsg.tid);

		TEST_NE(task, NULL);
		TEST_EQ(task->tid, tmsg.tid);

		sess = find_task_session(&test_sessions, task, tmsg.time);
		TEST_NE(sess, NULL);
		/* it returned a session from parent so pid is not same */
		TEST_NE(sess->pid, tmsg.pid);
		TEST_LE(sess->start_time, tmsg.time);
	}

	task = find_task(&test_sessions, 1);
	sess = find_task_session(&test_sessions, task, 100);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	task = find_task(&test_sessions, 2);
	sess = find_task_session(&test_sessions, task, 200);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	task = find_task(&test_sessions, 4);
	sess = find_task_session(&test_sessions, task, 400);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "initial");

	sess = find_task_session(&test_sessions, task, 500);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	task = find_task(&test_sessions, 5);
	sess = find_task_session(&test_sessions, task, 600);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	task = find_task(&test_sessions, 6);
	sess = find_task_session(&test_sessions, task, 700);
	TEST_NE(sess, NULL);
	TEST_STREQ(sess->sid, "after_exec");

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.tasks), true);

	return TEST_OK;
}

TEST_CASE(task_symbol)
{
	struct sym *sym;
	struct uftrace_msg_sess msg = {
		.task = {
			.pid = 1,
			.tid = 1,
			.time = 100,
		},
		.sid = "test",
		.namelen = 8,  /* = strlen("unittest") */
	};
	struct uftrace_msg_task tmsg = {
		.pid = 1,
		.tid = 1,
		.time = 100,
	};
	struct uftrace_task_reader task = {
		.tid = 1,
	};
	FILE *fp;

	fp = fopen("sid-test.map", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "%s", session_map);
	fclose(fp);

	fp = fopen("unittest.sym", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "00400100 P printf\n");
	fprintf(fp, "00400200 P __dynsym_end\n");
	fprintf(fp, "00400300 T _start\n");
	fprintf(fp, "00400400 T main\n");
	fprintf(fp, "00400500 T __sym_end\n");
	fclose(fp);

	create_session(&test_sessions, &msg, ".", "unittest", false);
	create_task(&test_sessions, &tmsg, false, true);
	remove("sid-test.map");
	remove("unittest.sym");

	TEST_NE(test_sessions.first, NULL);
	TEST_EQ(test_sessions.first->pid, 1);

	task.t = find_task(&test_sessions, 1);
	sym = task_find_sym_addr(&test_sessions, &task, 100, 0x400410);

	TEST_NE(sym, NULL);
	TEST_STREQ(sym->name, "main");

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);

	return TEST_OK;
}

TEST_CASE(task_symbol_dlopen)
{
	struct sym *sym;
	struct uftrace_msg_sess msg = {
		.task = {
			.pid = 1,
			.tid = 1,
			.time = 100,
		},
		.sid = "test",
		.namelen = 8,  /* = strlen("unittest") */
	};
	FILE *fp;

	fp = fopen("sid-test.map", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "%s", session_map);
	fclose(fp);

	fp = fopen("libuftrace-test.so.0.sym", "w");
	TEST_NE(fp, NULL);
	fprintf(fp, "0100 P __tls_get_addr\n");
	fprintf(fp, "0200 P __dynsym_end\n");
	fprintf(fp, "0300 T _start\n");
	fprintf(fp, "0400 T foo\n");
	fprintf(fp, "0500 T __sym_end\n");
	fclose(fp);

	create_session(&test_sessions, &msg, ".", "unittest", false);
	remove("sid-test.map");

	TEST_NE(test_sessions.first, NULL);
	TEST_EQ(test_sessions.first->pid, 1);

	session_add_dlopen(test_sessions.first, 200, 0x7003000, "libuftrace-test.so.0");
	remove("libuftrace-test.so.0.sym");

	TEST_EQ(list_empty(&test_sessions.first->dlopen_libs), false);

	sym = session_find_dlsym(test_sessions.first, 250, 0x7003410);

	TEST_NE(sym, NULL);
	TEST_STREQ(sym->name, "foo");

	delete_sessions(&test_sessions);
	TEST_EQ(RB_EMPTY_ROOT(&test_sessions.root), true);

	return TEST_OK;
}

#endif /* UNIT_TEST */
