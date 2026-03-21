import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';

/**
 ** Decorator to fetch refresh_token from cookie or Authorization header
 */
export const RTCookie = createParamDecorator(
  (data: unknown, context: ExecutionContext) => {
    let req: any;

    // Handle both REST and GQL contexts
    const contextType = context.getType<string>();
    if (contextType === 'graphql') {
      const ctx = GqlExecutionContext.create(context);
      req = ctx.getContext().req;
    } else {
      req = context.switchToHttp().getRequest();
    }

    // Try cookie first (web app)
    const cookieToken = req?.cookies?.['refresh_token'];
    if (cookieToken) return cookieToken;

    // Fall back to Authorization header (desktop app)
    const authHeader =
      req?.headers?.authorization || req?.headers?.['Authorization'];
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

    return undefined;
  },
);
