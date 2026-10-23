const request = require('supertest');

process.env.DB_PATH = ':memory:';

const { app, bootstrap } = require('../app');

function authHeader(token) {
  return { Authorization: 'Bearer ' + token };
}

async function login(email, password) {
  const response = await request(app).post('/login').send({ email, password });
  return response.body.token;
}

describe('collaborative project management API', () => {
  let adminToken;
  let memberToken;
  let projectId;
  let taskId;

  beforeAll(async () => {
    await bootstrap();
    adminToken = await login('admin@example.com', 'admin123');

    const member = await request(app)
      .post('/users')
      .set(authHeader(adminToken))
      .send({
        name: 'Member',
        email: 'member@example.com',
        password: 'password123',
        role: 'team_member',
      });

    const memberId = member.body.id;

    const project = await request(app)
      .post('/projects')
      .set(authHeader(adminToken))
      .send({ name: 'Project Alpha' });

    projectId = project.body.id;

    await request(app)
      .post(`/projects/${projectId}/team`)
      .set(authHeader(adminToken))
      .send({ user_id: memberId, role: 'team_member' });

    const task = await request(app)
      .post(`/projects/${projectId}/tasks`)
      .set(authHeader(adminToken))
      .send({ title: 'Initial task', assigned_to: memberId });

    taskId = task.body.id;
    memberToken = await login('member@example.com', 'password123');
  });

  it('rejects unauthorized project deletion for team member', async () => {
    const response = await request(app)
      .delete(`/projects/${projectId}`)
      .set(authHeader(memberToken));

    expect(response.status).toBe(403);
  });

  it('returns 409 when updating task with stale version', async () => {
    const currentTask = await request(app)
      .get(`/tasks/${taskId}`)
      .set(authHeader(memberToken));

    const staleVersion = currentTask.body.version;

    const firstUpdate = await request(app)
      .patch(`/tasks/${taskId}`)
      .set(authHeader(memberToken))
      .send({ version: staleVersion, status: 'in_progress' });

    expect(firstUpdate.status).toBe(200);
    expect(firstUpdate.body.version).toBe(staleVersion + 1);

    const conflictUpdate = await request(app)
      .patch(`/tasks/${taskId}`)
      .set(authHeader(memberToken))
      .send({ version: staleVersion, status: 'done' });

    expect(conflictUpdate.status).toBe(409);
    expect(conflictUpdate.body.error).toBe('Task version conflict');
    expect(conflictUpdate.body.latest.version).toBe(staleVersion + 1);
  });
});
