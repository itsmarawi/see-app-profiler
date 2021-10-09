export interface IOrganization  {
    name: string;
    code: string;  //ISO-CodeName
    description: string;
    parentOrgCode?: string;

    children: IOrganization[]; //computed from children.parentOrg
}