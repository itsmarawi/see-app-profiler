export class ProfilerException {
    constructor(public error:string, public code?:number) {}
    toString() {
        return `[Error] ${this.error} (${this.code})`
    }
}