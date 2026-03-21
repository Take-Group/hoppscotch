import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import {
  Injectable,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from 'src/user/user.service';
import { Request } from 'express';
import { RefreshTokenPayload } from 'src/types/AuthTokens';
import {
  COOKIES_NOT_FOUND,
  INVALID_REFRESH_TOKEN,
  USER_NOT_FOUND,
} from 'src/errors';
import * as O from 'fp-ts/Option';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class RTJwtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(
    private usersService: UserService,
    private configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          // Try cookie first (web app)
          const RTCookie = request.cookies?.['refresh_token'];
          if (RTCookie) return RTCookie;

          // Fall back to Authorization header (desktop app)
          const authHeader =
            request.headers?.authorization || request.headers?.['Authorization'];
          if (authHeader) {
            const headerValue = Array.isArray(authHeader)
              ? authHeader[0]
              : authHeader;
            if (
              typeof headerValue === 'string' &&
              headerValue.startsWith('Bearer ')
            ) {
              return headerValue.slice(7);
            }
          }

          console.error('`refresh_token` not found');
          throw new ForbiddenException(COOKIES_NOT_FOUND);
        },
      ]),
      secretOrKey: configService.get('INFRA.JWT_SECRET'),
    });
  }

  async validate(payload: RefreshTokenPayload) {
    if (!payload) throw new ForbiddenException(INVALID_REFRESH_TOKEN);

    const user = await this.usersService.findUserById(payload.sub);
    if (O.isNone(user)) {
      throw new UnauthorizedException(USER_NOT_FOUND);
    }

    return user.value;
  }
}
