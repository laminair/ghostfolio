import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-ldapauth';

import { AuthService } from './auth.service';

const getLdapConfig = (options: any) => {
  return {
    server: {
      url: options.url,
      bindDN: options.bindDN,
      bindCredentials: options.bindCredentials,
      searchBase: options.searchBase,
      searchFilter: options.searchFilter,
      searchAttributes: options.searchAttributes || ['displayName', 'mail', 'cn']
    }
  };
};

@Injectable()
export class LdapStrategy extends PassportStrategy(Strategy, 'ldap') {
  constructor(
    private readonly authService: AuthService,
    options: {
      url: string;
      bindDN: string;
      bindCredentials: string;
      searchBase: string;
      searchFilter: string;
      searchAttributes?: string[];
    }
  ) {
    super(getLdapConfig(options));
  }

  async validate(user: any): Promise<any> {
    const ldapId = user.dn || user.cn;
    const displayName = user.displayName || user.cn;
    const email = user.mail;

    try {
      const authToken = await this.authService.validateOAuthLogin({
        provider: 'LDAP',
        thirdPartyId: ldapId
      });

      return {
        jwt: authToken,
        user: {
          id: ldapId,
          displayName,
          email
        }
      };
    } catch (error) {
      return null;
    }
  }
}