# collaborative-project-management

Multi-user collaborative project management backend with role-based access control, optimistic concurrency for task updates, and CRUD APIs for users, projects, memberships, tasks, and comments.

## Run

```bash
npm install
npm start
```

Default admin credentials:
- Email: `admin@example.com`
- Password: `admin123`

## Test

```bash
npm test
```

## Key API Routes

- `POST /login`
- `GET /dashboard`
- `POST|GET|PATCH|DELETE /users`
- `POST|GET|PATCH|DELETE /projects`
- `GET|POST|PATCH|DELETE /projects/:id/team`
- `POST|GET /projects/:id/tasks`
- `GET|PATCH|DELETE /tasks/:id`
- `POST|GET /tasks/:id/comments`
- `DELETE /comments/:id`

Task updates require a `version` field and return `409` on stale updates.
