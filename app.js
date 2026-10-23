const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { all, get, run, initDb } = require('./db');
const { authenticate, requireGlobalRoles, signToken } = require('./auth');

const app = express();
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 200,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
  })
);

function parsePagination(query) {
  const limit = Math.min(Math.max(Number(query.limit) || 20, 1), 100);
  const offset = Math.max(Number(query.offset) || 0, 0);
  return { limit, offset };
}

async function getProjectMembership(projectId, userId) {
  return get(
    'SELECT role FROM project_members WHERE project_id = ? AND user_id = ?',
    [projectId, userId]
  );
}

async function canAccessProject(user, projectId) {
  if (user.role === 'admin') return { allowed: true, role: 'admin' };
  const membership = await getProjectMembership(projectId, user.id);
  if (membership) return { allowed: true, role: membership.role };
  return { allowed: false };
}

async function requireProjectAccess(req, res, next) {
  const projectId = Number(req.params.id || req.params.projectId);
  const access = await canAccessProject(req.user, projectId);
  if (!access.allowed) return res.status(403).json({ error: 'Forbidden' });
  req.projectRole = access.role;
  return next();
}

function requireProjectManagerOrAdmin(req, res, next) {
  if (req.user.role === 'admin' || req.projectRole === 'project_manager') {
    return next();
  }
  return res.status(403).json({ error: 'Forbidden' });
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = await get('SELECT * FROM users WHERE email = ? AND active = 1', [email]);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = signToken(user);
  return res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.get('/dashboard', authenticate, async (req, res) => {
  if (req.user.role === 'admin') {
    const summary = await get(
      'SELECT (SELECT COUNT(*) FROM projects WHERE archived = 0) AS active_projects, (SELECT COUNT(*) FROM tasks) AS tasks, (SELECT COUNT(*) FROM users WHERE active = 1) AS users'
    );
    return res.json(summary);
  }

  const projects = await get(
    'SELECT COUNT(*) AS projects FROM project_members WHERE user_id = ?',
    [req.user.id]
  );
  const tasks = await get(
    'SELECT COUNT(*) AS tasks FROM tasks WHERE assigned_to = ?',
    [req.user.id]
  );

  return res.json({ projects: projects.projects, tasks: tasks.tasks });
});

app.post('/users', authenticate, requireGlobalRoles('admin'), async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'Missing required fields' });

  const hash = await bcrypt.hash(password, 10);
  const result = await run(
    'INSERT INTO users(name, email, password_hash, role) VALUES(?,?,?,?)',
    [name, email, hash, role]
  );
  const created = await get('SELECT id, name, email, role, active FROM users WHERE id = ?', [result.lastID]);
  return res.status(201).json(created);
});

app.get('/users', authenticate, requireGlobalRoles('admin'), async (req, res) => {
  const { limit, offset } = parsePagination(req.query);
  const users = await all(
    'SELECT id, name, email, role, active, created_at, updated_at FROM users ORDER BY id LIMIT ? OFFSET ?',
    [limit, offset]
  );
  return res.json({ items: users, limit, offset });
});

app.patch('/users/:id', authenticate, async (req, res) => {
  const id = Number(req.params.id);
  if (req.user.role !== 'admin' && req.user.id !== id) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const existing = await get('SELECT * FROM users WHERE id = ?', [id]);
  if (!existing) return res.status(404).json({ error: 'User not found' });

  const name = req.body.name ?? existing.name;
  const role = req.user.role === 'admin' ? req.body.role ?? existing.role : existing.role;
  const active = req.user.role === 'admin' ? (req.body.active ?? existing.active) : existing.active;
  const passwordHash = req.body.password ? await bcrypt.hash(req.body.password, 10) : existing.password_hash;

  await run(
    'UPDATE users SET name = ?, role = ?, active = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [name, role, active ? 1 : 0, passwordHash, id]
  );

  const updated = await get('SELECT id, name, email, role, active, updated_at FROM users WHERE id = ?', [id]);
  return res.json(updated);
});

app.delete('/users/:id', authenticate, requireGlobalRoles('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const result = await run('UPDATE users SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [id]);
  if (!result.changes) return res.status(404).json({ error: 'User not found' });
  return res.status(204).send();
});

app.post('/projects', authenticate, requireGlobalRoles('admin'), async (req, res) => {
  const { name, description, project_manager_id } = req.body;
  if (!name) return res.status(400).json({ error: 'Project name is required' });

  const result = await run(
    'INSERT INTO projects(name, description, created_by, project_manager_id) VALUES(?,?,?,?)',
    [name, description ?? null, req.user.id, project_manager_id ?? null]
  );

  if (project_manager_id) {
    await run(
      'INSERT OR REPLACE INTO project_members(project_id, user_id, role) VALUES(?,?,?)',
      [result.lastID, project_manager_id, 'project_manager']
    );
  }

  const created = await get('SELECT * FROM projects WHERE id = ?', [result.lastID]);
  return res.status(201).json(created);
});

app.get('/projects', authenticate, async (req, res) => {
  const { limit, offset } = parsePagination(req.query);
  const includeArchived = req.query.includeArchived === 'true';

  let sql;
  let params;
  if (req.user.role === 'admin') {
    sql = 'SELECT * FROM projects WHERE (? = 1 OR archived = 0) ORDER BY id LIMIT ? OFFSET ?';
    params = [includeArchived ? 1 : 0, limit, offset];
  } else {
    sql = `
      SELECT p.*
      FROM projects p
      JOIN project_members pm ON pm.project_id = p.id
      WHERE pm.user_id = ? AND (? = 1 OR p.archived = 0)
      ORDER BY p.id LIMIT ? OFFSET ?
    `;
    params = [req.user.id, includeArchived ? 1 : 0, limit, offset];
  }

  const items = await all(sql, params);
  return res.json({ items, limit, offset });
});

app.get('/projects/:id', authenticate, async (req, res) => {
  const projectId = Number(req.params.id);
  const project = await get('SELECT * FROM projects WHERE id = ?', [projectId]);
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const access = await canAccessProject(req.user, projectId);
  if (!access.allowed) return res.status(403).json({ error: 'Forbidden' });

  return res.json(project);
});

app.patch('/projects/:id', authenticate, async (req, res) => {
  const projectId = Number(req.params.id);
  const project = await get('SELECT * FROM projects WHERE id = ?', [projectId]);
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const access = await canAccessProject(req.user, projectId);
  if (!(req.user.role === 'admin' || access.role === 'project_manager')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const name = req.body.name ?? project.name;
  const description = req.body.description ?? project.description;
  const archived = req.user.role === 'admin' ? (req.body.archived ?? project.archived) : project.archived;

  await run(
    'UPDATE projects SET name = ?, description = ?, archived = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [name, description, archived ? 1 : 0, projectId]
  );

  const updated = await get('SELECT * FROM projects WHERE id = ?', [projectId]);
  return res.json(updated);
});

app.delete('/projects/:id', authenticate, requireGlobalRoles('admin'), async (req, res) => {
  const projectId = Number(req.params.id);
  const result = await run('UPDATE projects SET archived = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [projectId]);
  if (!result.changes) return res.status(404).json({ error: 'Project not found' });
  return res.status(204).send();
});

app.get('/projects/:id/team', authenticate, requireProjectAccess, async (req, res) => {
  const projectId = Number(req.params.id);
  const team = await all(
    `SELECT pm.project_id, pm.user_id, pm.role, u.name, u.email
     FROM project_members pm JOIN users u ON u.id = pm.user_id
     WHERE pm.project_id = ? ORDER BY u.id`,
    [projectId]
  );
  return res.json(team);
});

app.post('/projects/:id/team', authenticate, requireProjectAccess, requireProjectManagerOrAdmin, async (req, res) => {
  const projectId = Number(req.params.id);
  const { user_id, role } = req.body;
  if (!user_id || !role) return res.status(400).json({ error: 'user_id and role are required' });

  const user = await get('SELECT id FROM users WHERE id = ? AND active = 1', [user_id]);
  if (!user) return res.status(404).json({ error: 'User not found' });

  await run(
    'INSERT OR REPLACE INTO project_members(project_id, user_id, role) VALUES(?,?,?)',
    [projectId, user_id, role]
  );

  const member = await get('SELECT project_id, user_id, role FROM project_members WHERE project_id = ? AND user_id = ?', [projectId, user_id]);
  return res.status(201).json(member);
});

app.patch('/projects/:id/team/:userId', authenticate, requireProjectAccess, requireProjectManagerOrAdmin, async (req, res) => {
  const projectId = Number(req.params.id);
  const userId = Number(req.params.userId);
  const role = req.body.role;
  if (!role) return res.status(400).json({ error: 'role is required' });

  const result = await run(
    'UPDATE project_members SET role = ? WHERE project_id = ? AND user_id = ?',
    [role, projectId, userId]
  );

  if (!result.changes) return res.status(404).json({ error: 'Team member not found' });
  const updated = await get('SELECT project_id, user_id, role FROM project_members WHERE project_id = ? AND user_id = ?', [projectId, userId]);
  return res.json(updated);
});

app.delete('/projects/:id/team/:userId', authenticate, requireProjectAccess, requireProjectManagerOrAdmin, async (req, res) => {
  const projectId = Number(req.params.id);
  const userId = Number(req.params.userId);
  const result = await run('DELETE FROM project_members WHERE project_id = ? AND user_id = ?', [projectId, userId]);
  if (!result.changes) return res.status(404).json({ error: 'Team member not found' });
  return res.status(204).send();
});

app.post('/projects/:id/tasks', authenticate, requireProjectAccess, async (req, res) => {
  if (!(req.user.role === 'admin' || req.projectRole === 'project_manager')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const projectId = Number(req.params.id);
  const { title, description, assigned_to, status } = req.body;
  if (!title) return res.status(400).json({ error: 'title is required' });

  const result = await run(
    'INSERT INTO tasks(project_id, title, description, assigned_to, status, created_by) VALUES(?,?,?,?,?,?)',
    [projectId, title, description ?? null, assigned_to ?? null, status ?? 'todo', req.user.id]
  );

  const created = await get('SELECT * FROM tasks WHERE id = ?', [result.lastID]);
  return res.status(201).json(created);
});

app.get('/projects/:id/tasks', authenticate, requireProjectAccess, async (req, res) => {
  const projectId = Number(req.params.id);
  const { limit, offset } = parsePagination(req.query);

  const statusFilter = req.query.status;
  const assigneeFilter = req.query.assigned_to;

  let sql = 'SELECT * FROM tasks WHERE project_id = ?';
  const params = [projectId];

  if (statusFilter) {
    sql += ' AND status = ?';
    params.push(statusFilter);
  }

  if (assigneeFilter) {
    sql += ' AND assigned_to = ?';
    params.push(Number(assigneeFilter));
  }

  sql += ' ORDER BY id LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const items = await all(sql, params);
  return res.json({ items, limit, offset });
});

app.get('/tasks/:id', authenticate, async (req, res) => {
  const taskId = Number(req.params.id);
  const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const access = await canAccessProject(req.user, task.project_id);
  if (!access.allowed) return res.status(403).json({ error: 'Forbidden' });

  return res.json(task);
});

app.patch('/tasks/:id', authenticate, async (req, res) => {
  const taskId = Number(req.params.id);
  const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const access = await canAccessProject(req.user, task.project_id);
  if (!access.allowed) return res.status(403).json({ error: 'Forbidden' });

  const incomingVersion = Number(req.body.version);
  if (!incomingVersion) {
    return res.status(400).json({ error: 'version is required for optimistic concurrency control' });
  }

  const isAdmin = req.user.role === 'admin';
  const isProjectManager = access.role === 'project_manager';
  const isAssignee = task.assigned_to === req.user.id;

  if (!(isAdmin || isProjectManager || isAssignee)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const title = req.body.title ?? task.title;
  const description = req.body.description ?? task.description;
  const status = req.body.status ?? task.status;

  let assignedTo = task.assigned_to;
  if (isAdmin || isProjectManager) {
    assignedTo = req.body.assigned_to ?? task.assigned_to;
  }

  const update = await run(
    `UPDATE tasks
     SET title = ?, description = ?, status = ?, assigned_to = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP
     WHERE id = ? AND version = ?`,
    [title, description, status, assignedTo, taskId, incomingVersion]
  );

  if (!update.changes) {
    const latest = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
    return res.status(409).json({ error: 'Task version conflict', latest });
  }

  const updated = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
  return res.json(updated);
});

app.delete('/tasks/:id', authenticate, async (req, res) => {
  const taskId = Number(req.params.id);
  const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const access = await canAccessProject(req.user, task.project_id);
  if (!(req.user.role === 'admin' || access.role === 'project_manager')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  await run('DELETE FROM tasks WHERE id = ?', [taskId]);
  return res.status(204).send();
});

app.post('/tasks/:id/comments', authenticate, async (req, res) => {
  const taskId = Number(req.params.id);
  const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const access = await canAccessProject(req.user, task.project_id);
  if (!access.allowed || access.role === 'viewer') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  if (!req.body.content) return res.status(400).json({ error: 'content is required' });

  const result = await run(
    'INSERT INTO comments(task_id, author_id, content) VALUES(?,?,?)',
    [taskId, req.user.id, req.body.content]
  );

  const created = await get('SELECT * FROM comments WHERE id = ?', [result.lastID]);
  return res.status(201).json(created);
});

app.get('/tasks/:id/comments', authenticate, async (req, res) => {
  const taskId = Number(req.params.id);
  const task = await get('SELECT * FROM tasks WHERE id = ?', [taskId]);
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const access = await canAccessProject(req.user, task.project_id);
  if (!access.allowed) return res.status(403).json({ error: 'Forbidden' });

  const comments = await all(
    `SELECT c.id, c.task_id, c.author_id, c.content, c.created_at, u.name AS author_name
     FROM comments c JOIN users u ON u.id = c.author_id
     WHERE c.task_id = ? ORDER BY c.id`,
    [taskId]
  );

  return res.json(comments);
});

app.delete('/comments/:id', authenticate, async (req, res) => {
  const commentId = Number(req.params.id);
  const comment = await get('SELECT * FROM comments WHERE id = ?', [commentId]);
  if (!comment) return res.status(404).json({ error: 'Comment not found' });

  const task = await get('SELECT * FROM tasks WHERE id = ?', [comment.task_id]);
  const access = await canAccessProject(req.user, task.project_id);
  const canDelete = req.user.role === 'admin' || access.role === 'project_manager' || comment.author_id === req.user.id;

  if (!canDelete) return res.status(403).json({ error: 'Forbidden' });

  await run('DELETE FROM comments WHERE id = ?', [commentId]);
  return res.status(204).send();
});

app.use((err, _req, res, _next) => {
  if (err && err.code === 'SQLITE_CONSTRAINT') {
    return res.status(400).json({ error: err.message });
  }
  return res.status(500).json({ error: 'Internal server error' });
});

async function bootstrap() {
  await initDb();
  return app;
}

module.exports = {
  app,
  bootstrap,
};
