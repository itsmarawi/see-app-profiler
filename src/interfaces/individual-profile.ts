export interface IIndividualProfile {
  id?: string;
  key?: string;
  code?: string;
  firstName: string;
  middleName: string;
  lastName: string;
  birthDate: string;
  gender: 'Male' | 'Female';
  activation?: string;
}
