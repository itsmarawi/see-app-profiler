import { IIndividualProfile } from './individual-profile';
import { IOrganization } from './organization';

export interface IAdminProfile extends IIndividualProfile {
    kind: 'admin';
}

export interface IExecutiveProfile extends IIndividualProfile{
    kind: 'executive';
    role: 'chief' | 'head-encoder' | 'manager';
    supervisor?: IExecutiveProfile | string;
    organization: IOrganization| string;
}

export interface IProfileEncoder extends IIndividualProfile {
    kind: 'encoder';
    executive?: IExecutiveProfile | string;
    organization: IOrganization| string;
}

export type EveryProfile = IAdminProfile | IProfileEncoder | IExecutiveProfile;

