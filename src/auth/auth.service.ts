import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger('AuthService')

    constructor(
        private readonly jwtService: JwtService, // Assuming JwtService is imported and used for token generation
    ) {
        super();
    }

    onModuleInit() {
        this.$connect()
        this.logger.log('Mongo connected successfully');
    }

    async signJWT( payload: JwtPayload ): Promise<string> {
        try {
            const token = this.jwtService.sign(payload);
            return token;
        } catch (error) {
            this.logger.error('Error signing JWT', error);
            throw new RpcException({
                status: 500,
                message: 'Internal server error'
            });
        }
    };

    async verifyToken(token: string) {

        try {
            const { sub, iat, exp, ...user} = this.jwtService.verify(token, {
                secret: envs.jwtSecret
            });

            return {
                user: user,
                token: await this.signJWT(user as JwtPayload)
            };
        } catch (error) {
            console.error('Error verifying token', error);
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            });
            
        }
    }

    async registerUser( registerUserDto: RegisterUserDto ){

        const { email, name, password } = registerUserDto;

        try {

            const user = await this.user.findUnique({
                where: { 
                    email: email,
                 }
            });

            if (user) {
                throw new Error('User already exists');
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    name,
                    password: bcrypt.hashSync(password, 10)
                }
            });

            const { password: _, ...userWithoutPassword } = newUser;

            return {
                user: userWithoutPassword,
                token: await this.signJWT( userWithoutPassword as JwtPayload )
            }
            
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    };

    async loginUser( loginUserDto: LoginUserDto ){

        const { email, password } = loginUserDto;

        try {

            const user = await this.user.findUnique({
                where: { 
                    email: email,
                 }
            });

            if (!user) {
                throw new Error('Invalid: User/Password');
            }

            const isPasswordvalid = bcrypt.compareSync(password, user.password);
            if (!isPasswordvalid) {
                throw new Error('Invalid: User/Password');
            }

            const { password: _, ...userWithoutPassword } = user;

            return {
                user: userWithoutPassword,
                token: await this.signJWT( userWithoutPassword as JwtPayload )
            }
            
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    };

    
}
