import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { cookies } from 'next/headers';

// Mock user database - replace with real database
const users = [
  {
    id: 1,
    username: 'admin',
    password: '$2a$10$8K1p/a0dL2LkYHZxq5YZ3uJ7nZXJ5nZXJ5nZXJ5nZXJ5nZXJ5nZXJ5' // 'password'
  }
];

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export async function POST(request) {
  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return NextResponse.json(
        { message: 'Username and password required' },
        { status: 400 }
      );
    }

    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
      return NextResponse.json(
        { message: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // For demo purposes, allow 'password' as plain text or check hashed
    const isValidPassword = password === 'password' || await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return NextResponse.json(
        { message: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Set cookie
    const cookieStore = cookies();
    cookieStore.set('auth-token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 86400, // 24 hours
      path: '/'
    });

    return NextResponse.json({
      message: 'Login successful',
      user: { username: user.username }
    });
  } catch (error) {
    return NextResponse.json(
      { message: 'Internal server error' },
      { status: 500 }
    );
  }
}
