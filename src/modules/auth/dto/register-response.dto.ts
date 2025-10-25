export class RegisterResponseDto {
  user: {
    id: string;
    email: string;
    fullName: string;
    role: 'guest' | 'admin' | 'sysadmin';
    emailVerified: boolean;
  };
}
