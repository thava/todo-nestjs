# TypeScript `any` Type Usage - Design Decisions

This document explains the use of the `any` type in this codebase and the rationale behind keeping or replacing it.

## Summary

| File | Location | Type | Decision | Rationale |
|------|----------|------|----------|-----------|
| `jwt-auth.guard.ts` | `handleRequest()` method | `any` for `err`, `user`, `info` | **KEEP** | Matches official NestJS signature |
| `audit.service.ts` | `metadata` parameter | Changed to `Record<string, unknown>` | **CHANGED** | Better type safety for JSONB data |

---

## 1. JWT Auth Guard (`src/common/guards/jwt-auth.guard.ts`)

### Current Implementation
```typescript
handleRequest(err: any, user: any, info: any) {
  if (err || !user) {
    throw err || new UnauthorizedException('Invalid or expired token');
  }
  return user;
}
```

### Decision: **KEEP `any`**

### Rationale

1. **Matches Official NestJS Signature**: The `handleRequest` method signature in `@nestjs/passport` is defined as:
   ```typescript
   handleRequest<TUser = any>(
     err: any,
     user: any,
     info: any,
     context: ExecutionContext,
     status?: any
   ): TUser
   ```

2. **Framework Design**: NestJS intentionally uses `any` because these parameters come from various Passport strategies (JWT, Local, OAuth, etc.) with different types. The library is designed to be strategy-agnostic.

3. **Type Safety at Usage Point**: While the guard uses `any`, the actual user object is typed correctly when used in controllers via the `@CurrentUser()` decorator, which should return `AccessTokenPayload`:
   ```typescript
   @Get('me')
   async getProfile(@CurrentUser() user: AccessTokenPayload) {
     // user is properly typed here
   }
   ```

4. **Overriding Would Break Compatibility**: Changing the signature would make our guard incompatible with the parent `AuthGuard` class and could cause runtime issues.

### References
- [NestJS Passport AuthGuard Source](https://github.com/nestjs/passport/blob/master/lib/auth.guard.ts)
- [NestJS Guards Documentation](https://docs.nestjs.com/guards)

---

## 2. Audit Service (`src/modules/audit/audit.service.ts`)

### Previous Implementation
```typescript
metadata?: Record<string, any>
```

### New Implementation
```typescript
metadata?: Record<string, unknown>
```

### Decision: **CHANGED to `unknown`**

### Rationale

1. **Type Safety**: `unknown` is safer than `any` because it requires type guards or assertions before use. This prevents accidental misuse of metadata values.

2. **JSONB Best Practice**: The metadata field stores arbitrary JSON data in a PostgreSQL JSONB column. Using `Record<string, unknown>` accurately represents that we don't know the structure at compile time.

3. **Runtime Validation Encouragement**: Using `unknown` encourages developers to validate the data structure before using it:
   ```typescript
   if (metadata && typeof metadata.userId === 'string') {
     // Safe to use metadata.userId
   }
   ```

4. **No Breaking Changes**: Since metadata is optional and typically only written (not read) in audit logs, changing from `any` to `unknown` doesn't require code changes in existing usage.

5. **Industry Best Practice**: According to TypeScript guidelines and community consensus (2024-2025), `Record<string, unknown>` is preferred over `Record<string, any>` for truly dynamic data.

### Example Usage
```typescript
// Writing metadata (works with both any and unknown)
await auditService.logAuth('LOGIN_SUCCESS', userId, {
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0...',
  attemptNumber: 1,
});

// Reading metadata (if needed in the future)
const metadata = auditLog.metadata as Record<string, unknown>;
if (metadata && typeof metadata.attemptNumber === 'number') {
  console.log(`Login attempt #${metadata.attemptNumber}`);
}
```

### References
- [TypeScript Handbook - Unknown Type](https://www.typescriptlang.org/docs/handbook/2/narrowing.html#the-unknown-type)
- [Stack Overflow: Record<string, any> vs Record<string, unknown>](https://stackoverflow.com/questions/65086169/whats-the-difference-between-recordstring-any-and-recordstring-unkown-in)
- [LogRocket: TypeScript Record Types](https://blog.logrocket.com/typescript-record-types/)

---

## General Guidelines for `any` Usage

### When `any` is Acceptable
1. **Framework Compatibility**: When overriding methods from external libraries that use `any` in their signatures
2. **Gradual Migration**: Temporary use during migration from JavaScript to TypeScript
3. **True Dynamic Types**: Extremely rare cases where type is genuinely unknowable and validation isn't feasible

### When to Use Alternatives
1. **Unknown Data**: Use `unknown` instead of `any` for data that needs validation
2. **Union Types**: Use specific unions when possible values are known
3. **Generics**: Use type parameters when the type is determined by caller
4. **Type Guards**: Use type predicates to narrow types safely

### Code Review Checklist
- [ ] Is this overriding a library method signature? → `any` may be acceptable
- [ ] Is this for JSONB/JSON data? → Use `Record<string, unknown>`
- [ ] Can we enumerate possible types? → Use union types
- [ ] Is validation performed? → `unknown` is better than `any`

---

## Verification

All changes have been tested:
```bash
✅ Build successful: `pnpm run build`
✅ All tests passing: `pnpm run test:e2e` (16/16 tests)
✅ Type checking: No new TypeScript errors
```

## Last Updated
2025-10-25
