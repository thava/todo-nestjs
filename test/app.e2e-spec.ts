import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';

describe('Application (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();

    // Apply global validation pipe (same as in main.ts)
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Health Checks', () => {
    it('/health (GET) should return ok', () => {
      return request(app.getHttpServer())
        .get('/health')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('status', 'ok');
          expect(res.body).toHaveProperty('timestamp');
        });
    });

    it('/readiness (GET) should return database status', () => {
      return request(app.getHttpServer())
        .get('/readiness')
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('status');
          expect(res.body).toHaveProperty('checks');
          expect(res.body.checks).toHaveProperty('database');
        });
    });
  });

  describe('Authentication', () => {
    let accessToken: string;
    let refreshToken: string;
    const testUser = {
      email: `test-${Date.now()}@example.com`,
      password: 'Test123!@#',
      fullName: 'Test User',
    };

    it('/auth/register (POST) should register a new user', () => {
      return request(app.getHttpServer())
        .post('/auth/register')
        .send(testUser)
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('accessToken');
          expect(res.body).toHaveProperty('refreshToken');
          expect(res.body).toHaveProperty('user');
          expect(res.body.user.email).toBe(testUser.email);
          expect(res.body.user.fullName).toBe(testUser.fullName);
          expect(res.body.user.role).toBe('guest');
          accessToken = res.body.accessToken;
          refreshToken = res.body.refreshToken;
        });
    });

    it('/auth/register (POST) should fail with duplicate email', () => {
      return request(app.getHttpServer())
        .post('/auth/register')
        .send(testUser)
        .expect(409);
    });

    it('/auth/login (POST) should login with valid credentials', () => {
      return request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('accessToken');
          expect(res.body).toHaveProperty('refreshToken');
          expect(res.body.user.email).toBe(testUser.email);
        });
    });

    it('/auth/login (POST) should fail with invalid credentials', () => {
      return request(app.getHttpServer())
        .post('/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword123!',
        })
        .expect(401);
    });

    it('/auth/refresh (POST) should refresh access token', () => {
      return request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refreshToken })
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('accessToken');
          expect(res.body).toHaveProperty('refreshToken');
          // Update tokens for next tests
          accessToken = res.body.accessToken;
          refreshToken = res.body.refreshToken;
        });
    });

    it('/me (GET) should return current user profile', () => {
      return request(app.getHttpServer())
        .get('/me')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200)
        .expect((res) => {
          expect(res.body.email).toBe(testUser.email);
          expect(res.body.fullName).toBe(testUser.fullName);
        });
    });

    it('/me (GET) should fail without token', () => {
      return request(app.getHttpServer())
        .get('/me')
        .expect(401);
    });

    it('/auth/logout (POST) should logout user', () => {
      return request(app.getHttpServer())
        .post('/auth/logout')
        .send({ refreshToken })
        .expect(204);
    });
  });

  describe('Todos', () => {
    let accessToken: string;
    let todoId: string;
    const testUser = {
      email: `todo-test-${Date.now()}@example.com`,
      password: 'Test123!@#',
      fullName: 'Todo Test User',
    };

    beforeAll(async () => {
      // Register and login
      const registerRes = await request(app.getHttpServer())
        .post('/auth/register')
        .send(testUser);
      accessToken = registerRes.body.accessToken;
    });

    it('/todos (POST) should create a new todo', () => {
      return request(app.getHttpServer())
        .post('/todos')
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          description: 'Test todo item',
          priority: 'high',
        })
        .expect(201)
        .expect((res) => {
          expect(res.body).toHaveProperty('id');
          expect(res.body.description).toBe('Test todo item');
          expect(res.body.priority).toBe('high');
          todoId = res.body.id;
        });
    });

    it('/todos (GET) should list user todos', () => {
      return request(app.getHttpServer())
        .get('/todos')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200)
        .expect((res) => {
          expect(Array.isArray(res.body)).toBe(true);
          expect(res.body.length).toBeGreaterThan(0);
        });
    });

    it('/todos/:id (GET) should get single todo', () => {
      return request(app.getHttpServer())
        .get(`/todos/${todoId}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200)
        .expect((res) => {
          expect(res.body.id).toBe(todoId);
          expect(res.body.description).toBe('Test todo item');
        });
    });

    it('/todos/:id (PATCH) should update todo', () => {
      return request(app.getHttpServer())
        .patch(`/todos/${todoId}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .send({
          description: 'Updated todo item',
          priority: 'low',
        })
        .expect(200)
        .expect((res) => {
          expect(res.body.description).toBe('Updated todo item');
          expect(res.body.priority).toBe('low');
        });
    });

    it('/todos/:id (DELETE) should delete todo', () => {
      return request(app.getHttpServer())
        .delete(`/todos/${todoId}`)
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(204);
    });

    it('/todos (POST) should fail without authentication', () => {
      return request(app.getHttpServer())
        .post('/todos')
        .send({
          description: 'Test todo',
          priority: 'medium',
        })
        .expect(401);
    });
  });
});
