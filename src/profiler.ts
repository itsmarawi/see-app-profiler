import * as nacl from 'tweetnacl';
import * as NaclUtil from 'tweetnacl-util';

import { EveryProfile, IExecutiveProfile, IProfileEncoder } from './interfaces/every-profile';
import { IIndividualProfile } from './interfaces/individual-profile';
import { ProfilerException } from './profiler.exception';
type ProfileTypes = 'admin' | 'executive' | 'encoder';
type RoleTypes = 'chief' | 'head';
export abstract class Profiler<P extends EveryProfile> {
    //{ Abstract Methods
    abstract getPubKey(kind: 'admin' | 'chief' | 'encoder', orgCode?: string): Promise<string>;
    abstract getPrivKey(kind: 'chief' | 'encoder', orgCode?: string): Promise<string>;
    abstract findOne(orgCode: string, profileId: string): Promise<P>;
    abstract findOneByCode(code: string): Promise<P>;
    abstract update(id: string, newItem: P): Promise<P>;
    abstract isOrgPartOfOrg(org: string, partentOrg: string): Promise<boolean>
    //} Abstract Methods
    //{ Profile Validation
    async validateProfileActivation(activation: string, profile: P) {
        if (profile.kind == 'encoder') {
            await this.validateEncoderActivation(activation, profile);
        } else if (profile.kind == 'executive' && profile.role != 'chief') {
            await this.validateExecutiveActivation(activation, profile);
        } else if (profile.kind == 'executive' && profile.role == 'chief') {
            await this.validateChiefActivation(activation, profile);
        } else if (profile.kind == 'admin') {
            await this.validateAdminActivation(activation, profile);
        }
        else {
            throw new ProfilerException('invalid-profile', 400);
        }
        profile.activation = activation;
        if (profile.id) {
            await this.update(profile.id, profile);
        } else {
            throw new ProfilerException('Unknown Profile', 417);
        }
        return profile;
    }
    private async validateAdminActivation(activation: string, profile: P) {
        const activationPubKey = await this.getPubKey('admin');
        if (activationPubKey) {
            const pubKey = NaclUtil.decodeBase64(activationPubKey);
            try {
                const decoded = nacl.sign.open(
                    NaclUtil.decodeBase64(activation),
                    pubKey);
                if (!decoded) throw new ProfilerException('permission-denied', 403);
                this.encodeCodeName(profile);
                const activationKey = NaclUtil.encodeUTF8(decoded).trim();
                //[ProfileCodeName:22]ACTIVATE:administrator
                const activationInfo = /^(?<ProfileCodeName>.{22})ACTIVATE:administrator/.exec(activationKey);
                if (!activationInfo || activationInfo.groups && profile.code !== activationInfo.groups['ProfileCodeName']) {
                    throw new ProfilerException('permission-denied', 403);
                }
            } catch (error) {
                throw new ProfilerException('invalid-activation', 403);
            }
        } else {
            throw new ProfilerException('no-activation-pub-keys', 417);
        }
    }
    private async validateChiefActivation(activation: string, profile: IExecutiveProfile) {
        const activationPubKey = await this.getPubKey('admin');
        if (activationPubKey) {
            const pubKey = NaclUtil.decodeBase64(activationPubKey);
            try {
                const decoded = nacl.sign.open(
                    NaclUtil.decodeBase64(activation),
                    pubKey);
                if (!decoded) throw new ProfilerException('permission-denied', 403);
                this.encodeCodeName(profile);
                const activationKey = NaclUtil.encodeUTF8(decoded).trim();
                //[Org:9][ProfileCodeName:22]ACTIVATE:[ROLE:#]
                const activationInfo = /^(?<Org>.{9})(?<ProfileCodeName>.{22})ACTIVATE:(?<Role>.*)/.exec(activationKey);
                if (!activationInfo ||
                    activationInfo.groups && (profile.organization !== activationInfo.groups['Org']
                        || profile.code !== activationInfo.groups['ProfileCodeName']
                        || (profile.kind == 'executive' && profile.role !== 'chief')
                        || (profile.kind == 'executive' && profile.role !== activationInfo.groups['Role']))) {
                    throw new ProfilerException('permission-denied', 403);
                }
            } catch (error) {
                throw new ProfilerException('invalid-activation:' + error, 403);
            }
        } else {
            throw new ProfilerException('no-activation-pub-keys', 417);
        }
    }
    private async validateExecutiveActivation(activation: string, profile: IExecutiveProfile) {
        if (!profile.supervisor) {
            throw new ProfilerException('permission-denied', 403);
        }
        const chief = typeof profile.supervisor == 'string'
            ? await this.findOneByCode(profile.supervisor) as IExecutiveProfile
            : profile.supervisor;
        if (chief.role != 'chief') {
            throw new ProfilerException('invalid-supervisor', 403);
        }
        const orgCode = typeof chief.organization == 'string'
            ? chief.organization : chief.organization.code;
        const authKey = await this.getPubKey('chief', orgCode);
        if (authKey) {
            try {
                const pubKey = NaclUtil.decodeBase64(authKey);
                const decoded = nacl.sign.open(
                    NaclUtil.decodeBase64(activation),
                    pubKey);
                if (!decoded) throw new ProfilerException('permission-denied', 403);
                this.encodeCodeName(profile);
                const activationKey = NaclUtil.encodeUTF8(decoded).trim();
                //[Org:9][ProfileCodeName:22][ChiefCodeName:22]ACTIVATE:[ROLE:#]
                const activationInfo = /^(?<Org>.{9})(?<ProfileCodeName>.{22})(?<ChiefCodeName>.{22})ACTIVATE:(?<Role>.*)/.exec(activationKey);
                const supCodeName = typeof profile.supervisor == 'string'
                    ? profile.supervisor : profile.supervisor.code;
                if (!activationInfo
                    || activationInfo.groups && (profile.organization !== activationInfo.groups['Org']
                        || profile.code !== activationInfo.groups['ProfileCodeName']
                        || (profile.role == 'chief')
                        || (supCodeName !== activationInfo.groups['ChiefCodeName']))) {
                    throw new ProfilerException('permission-denied', 403);
                }
                profile.role = this.validateRole(activationInfo.groups && activationInfo.groups['Role']);
            } catch (error) {
                throw new ProfilerException('invalid-activation', 403);
            }
        } else {
            throw new ProfilerException('no-keys', 417);
        }
    }
    private async validateEncoderActivation(activation: string, profile: IProfileEncoder) {
        if (!profile.executive) {
            throw new ProfilerException('permission-denied', 403);
        }
        const headProfiler = typeof profile.executive == 'string'
            ? await this.findOneByCode(profile.executive) as IExecutiveProfile
            : profile.executive;
        if ((typeof headProfiler.organization == 'string' && headProfiler.organization != profile.organization)) {
            throw new ProfilerException('invalid-executive', 403);
        }
        const chief = typeof headProfiler.supervisor == 'string'
            ? await this.findOneByCode(headProfiler.supervisor) as IExecutiveProfile
            : headProfiler.supervisor;
        if (!chief || chief.role != 'chief') {
            throw new ProfilerException('invalid-supervisor', 403);
        }
        const orgCode = typeof chief.organization == 'string'
            ? chief.organization : chief.organization.code;
        const authKey = await this.getPubKey('encoder', orgCode);
        if (authKey) {
            try {
                const pubKey = NaclUtil.decodeBase64(authKey);
                const decoded = nacl.sign.open(
                    NaclUtil.decodeBase64(activation),
                    pubKey);
                if (!decoded) throw new ProfilerException('permission-denied', 403);
                this.encodeCodeName(profile);
                const activationKey = NaclUtil.encodeUTF8(decoded).trim();
                //[Org:9][ProfileCodeName:22][ExecutiveCodeName:22]ACTIVATE:[ROLE:#]
                const activationInfo = /^(?<Org>.{9})(?<ProfileCodeName>.{22})(?<ExecutiveCodeName>.{22})ACTIVATE:(?<Role>.*)/.exec(activationKey);
                const execCodeName = typeof profile.executive == 'string' ? profile.executive : profile.executive?.code;
                if (!activationInfo
                    || activationInfo.groups && (profile.organization !== activationInfo.groups['Org']
                        || profile.code !== activationInfo.groups['ProfileCodeName']
                        || profile.kind !== activationInfo.groups['Role']
                        || (execCodeName !== activationInfo.groups['ExecutiveCodeName']))) {
                    throw new ProfilerException('permission-denied', 403);
                }
            } catch (error) {
                throw new ProfilerException('invalid-activation', 403);
            }
        } else {
            throw new ProfilerException('no-keys', 417);
        }
    }
    //} Profile Validation
    //{ Activation Generation
    async getAdminActivation(profileId: string, encryptionKey: string): Promise<string> {
        const profile = await this.findOne('no-org', profileId);
        if (profile.kind != 'admin') {
            throw new ProfilerException('invalid profile', 400);
        }
        let activationKey = profile.code + 'ACTIVATE:administrator';
        let encrypted = '=';
        do {
            encrypted = NaclUtil.encodeBase64(
                nacl.sign(NaclUtil.decodeUTF8(activationKey), NaclUtil.decodeBase64(encryptionKey))
            );
            activationKey += ' ';
        } while (!encrypted.endsWith('='));
        return encrypted;
    }
    async getChiefExecutiveActivation(orgCode: string, profileId: string, encryptionKey: string): Promise<string> {
        const profile = await this.findOne(orgCode, profileId);
        if (profile.kind != 'executive' || profile.role !== 'chief' || profile.supervisor) {
            throw new ProfilerException('invalid profile', 400);
        }
        if (profile.organization != orgCode) {
            throw new ProfilerException('Cannot activate across-organization', 400);
        }

        let activationKey = orgCode + profile.code + 'ACTIVATE:' + profile.role;
        let encrypted = '=';
        do {
            encrypted = NaclUtil.encodeBase64(
                nacl.sign(NaclUtil.decodeUTF8(activationKey), NaclUtil.decodeBase64(encryptionKey))
            );
            activationKey += ' ';
        } while (!encrypted.endsWith('='));
        return encrypted;
    }
    async getExecutiveActivation(orgCode: string, profileId: string, chiefOrg: string): Promise<string> {
        const profile = await this.findOne(orgCode, profileId);
        let supervisor: IExecutiveProfile;
        if (profile.kind == 'executive' && profile.supervisor) {
            supervisor = typeof profile.supervisor == 'string'
                ? await this.findOneByCode(profile.supervisor) as IExecutiveProfile
                : profile.supervisor;
        } else {
            throw new ProfilerException('invalid profile', 400);
        }
        if (typeof profile.organization == 'object' &&
            (profile.organization.parentOrgCode && (profile.organization.parentOrgCode !== supervisor.organization
                || profile.organization.parentOrgCode !== chiefOrg)
                || (!profile.organization.parentOrgCode && profile.organization.code !== chiefOrg))) {
            throw new ProfilerException('Cannot activate across-organization', 400);
        }
        const secretKey = await this.getPrivKey('chief', chiefOrg);

        if (!secretKey) {
            throw new ProfilerException('No Keys', 424);
        }

        let activationKey = orgCode + profile.code + supervisor.code + 'ACTIVATE:' + profile.role;
        let encrypted = '=';
        do {
            encrypted = NaclUtil.encodeBase64(
                nacl.sign(NaclUtil.decodeUTF8(activationKey), NaclUtil.decodeBase64(secretKey))
            );
            activationKey += ' ';
        } while (!encrypted.endsWith('='));
        return encrypted;
    }
    async getEncoderActivation(orgCode: string, profileId: string, executiveOrg: string): Promise<string> {
        const profile = await this.findOne(orgCode, profileId);

        if (profile.kind != 'encoder') {
            throw new ProfilerException('invalid profile id', 400);
        }
        if (typeof profile.executive == 'string') {
            profile.executive = await this.findOneByCode(profile.executive) as IExecutiveProfile;
        }
        if (!profile.executive) throw new ProfilerException('invalid profile executive', 400);

        if (await this.isOrgPartOfOrg(typeof profile.organization == 'object'
            ? profile.organization.code : profile.organization, executiveOrg) == false) {
            throw new ProfilerException('Cannot activate across-organization', 400);
        }
        const chief = typeof profile.executive.supervisor == 'string'
            ? await this.findOneByCode(profile.executive.supervisor) as IExecutiveProfile
            : profile.executive.supervisor;
        if (!chief || chief.role != 'chief') {
            throw new ProfilerException('invalid-supervisor', 403);
        }
        const chiefOrgCode = typeof chief.organization == 'string'
            ? chief.organization : chief.organization.code;
        const secretKey = await this.getPrivKey('encoder', chiefOrgCode);
        if (!secretKey) {
            throw new ProfilerException('No Keys', 424);
        }
        let activationKey = orgCode + profile.code + profile.executive.code + 'ACTIVATE:' + profile.kind;
        let encrypted = '=';
        do {
            encrypted = NaclUtil.encodeBase64(
                nacl.sign(NaclUtil.decodeUTF8(activationKey), NaclUtil.decodeBase64(secretKey))
            );
            activationKey += ' ';
        } while (!encrypted.endsWith('='));
        return encrypted;
    }
    //} Activation Generation
    //{ Profilling
    async encodeInfo(info: string, chiefOrg: string) {
        const secretKey = await this.getPrivKey('encoder', chiefOrg);
        if (!secretKey) {
            throw new ProfilerException('No Keys', 424);
        }
        let profileKey = info;
        let encrypted = '=';
        do {
            encrypted = NaclUtil.encodeBase64(
                nacl.sign(NaclUtil.decodeUTF8(profileKey), NaclUtil.decodeBase64(secretKey))
            );
            profileKey += ' ';
        } while (!encrypted.endsWith('='));
        return encrypted;
    }
    async decodeInfo(encrypted: string, authKey?: string, orgCode?: string) {
        if (!authKey) {
            authKey = await this.getPubKey('encoder', orgCode);
        }
        if (!authKey) {
            throw new ProfilerException('no-keys', 417);
        }
        try {
            const pubKey = NaclUtil.decodeBase64(authKey);
            const decoded = nacl.sign.open(
                NaclUtil.decodeBase64(encrypted),
                pubKey);
            if (!decoded) throw new ProfilerException('permission-denied', 403);
            return NaclUtil.encodeUTF8(decoded);
        } catch (error) {
            throw new ProfilerException('invalid-activation', 403);
        }
    }
    async generateProfile(profileCode: string, encoderCode: string, extraInfo?: string): Promise<string> {
        const profile = await this.findOneByCode(profileCode);
        const encoder = await this.findOneByCode(encoderCode);
        if (encoder.kind != 'encoder' || typeof encoder.executive !== 'object') {
            throw new ProfilerException('invalid profile id', 400);
        }
        const orgCode = typeof encoder.organization == 'string' ?
            encoder.organization : encoder.organization.code;

        const chief = typeof encoder.executive.supervisor == 'string'
            ? await this.findOneByCode(encoder.executive.supervisor) as IExecutiveProfile
            : encoder.executive.supervisor;
        if (!chief || chief.role != 'chief') {
            throw new ProfilerException('invalid-supervisor', 403);
        }
        const chiefOrgCode = typeof chief.organization == 'string'
            ? chief.organization : chief.organization.code;
        const secretKey = await this.getPrivKey('encoder', chiefOrgCode);
        if (!secretKey) {
            throw new ProfilerException('No Keys', 424);
        }
        let profileKey = orgCode + profile.code + encoder.code + encoder.executive.code + chief.code
            + 'PROFILED:' + profile.kind + ':' + String(extraInfo);
        let encrypted = '=';
        do {
            encrypted = NaclUtil.encodeBase64(
                nacl.sign(NaclUtil.decodeUTF8(profileKey), NaclUtil.decodeBase64(secretKey))
            );
            profileKey += ' ';
        } while (!encrypted.endsWith('='));
        return encrypted;
    }
    validateProrile(profileKey: string, authKey: string) {
        if (authKey) {
            try {
                const pubKey = NaclUtil.decodeBase64(authKey);
                const decoded = nacl.sign.open(
                    NaclUtil.decodeBase64(profileKey),
                    pubKey);
                if (!decoded) throw new ProfilerException('permission-denied', 403);
                const profiledKey = NaclUtil.encodeUTF8(decoded).trim();
                //[organization:9][code:22][encoder:22][executive:22][chief:22]PROFILED:[role:#]:[extra]
                const profileInfo = /^(?<organization>.{9})(?<code>.{22})(?<encoder>.{22})(?<executive>.{22})(?<chief>.{22})PROFILED:(?<role>[^:]+):(?<extra>.*)/
                    .exec(profiledKey);
                if (!profileInfo || !profileInfo.groups) {
                    throw new ProfilerException('Invalid Profile', 403);
                }
                return profileInfo.groups as {
                    organization: string, code: string, encoder: string, executive: string, chief: string,
                    role: string, extra: string
                };
            } catch (error) {
                throw new ProfilerException('invalid-activation', 403);
            }
        } else {
            throw new ProfilerException('no-keys', 417);
        }
    }
    //} Profilling
    //{ Helper Methods
    private validateRole(role?: string) {
        switch (role) {
            case 'chief': case 'Chief': case 'CHIEF':
                return 'chief';
            case 'head-encoder': case 'Head-Encoder': case 'HEAD-ENCODER':
                return 'head-encoder';
            default:
                return 'manager';
        }
    }
    protected encodeCodeName<P1 extends IIndividualProfile & { kind: string }>(profile: P1) {
        profile.firstName = String(profile.firstName).trim();
        if (!profile.firstName) throw new Error('First name is required');
        profile.middleName = String(profile.middleName).trim();
        if (!profile.middleName) throw new Error('Middle First name is required');
        profile.lastName = String(profile.lastName).trim();
        if (!profile.lastName) throw new Error('Last name is required');

        const birthDateExp = /^(\d{2})[-\/](\d{2})[-\/](\d{4})$/;
        const birthMatch = birthDateExp.exec(profile.birthDate);
        if (birthMatch == null) throw new Error('Invalid Birthdate');
        const mask = '0000' + birthMatch[1] + birthMatch[2] + birthMatch[3];
        const genderPart = profile.gender == 'Male' ? '1' : '0';
        profile.code = `${profile.firstName[0].toUpperCase()
            }${profile.middleName[0].toUpperCase()
            }${profile.lastName[0].toUpperCase()
            }${String(this.hashName(
                profile.firstName.toUpperCase()
                + profile.middleName[0].toUpperCase()
                + profile.lastName.toUpperCase()
                + profile.birthDate
                + profile.kind
            )).padEnd(mask.length, mask)
            }${genderPart}${birthMatch[1] + birthMatch[2] + birthMatch[3].substr(-2)
            }`;
        return profile;
    }
    protected decodeCodeName(codeName: string) {
        const profileInfo = /^(?<initials>[A-Z]{3})(?<hash>[-0-9]{12})(?<gender>[01])(?<bmonth>\d{2})(?<bday>\d{2})(?<byear>\d{2})/.exec(codeName);
        if (!profileInfo || !profileInfo.groups) {
            throw new ProfilerException('Invalid Code Name', 403);
        }
        const result = profileInfo.groups;
        return {
            initials: result.initials,
            hash: result.hash,
            gender: result.gender == '1' ? 'Male' : 'Female',
            birthDate: `${result.bmonth}-${result.bday}-${result.byear}`
        };
    }
    private hashName(name: string) {
        let hash = 0;
        if (name.length == 0) return hash;
        for (let i = 0; i < name.length; i++) {
            const chr = name.charCodeAt(i);
            hash = ((hash << 5) - hash) + chr;
            hash = hash & hash;
        }
        return hash;
    }
    //{ Helper Methods
}