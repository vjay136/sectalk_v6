export const indiaStates:Record<string,string>={
  '01':'Jammu and Kashmir','02':'Himachal Pradesh','03':'Punjab','04':'Chandigarh','05':'Uttarakhand','06':'Haryana',
  '07':'Delhi','08':'Rajasthan','09':'Uttar Pradesh','10':'Bihar','11':'Sikkim','12':'Arunachal Pradesh','13':'Nagaland',
  '14':'Manipur','15':'Mizoram','16':'Tripura','17':'Meghalaya','18':'Assam','19':'West Bengal','20':'Jharkhand',
  '21':'Odisha','22':'Chhattisgarh','23':'Madhya Pradesh','24':'Gujarat','26':'Dadra and Nagar Haveli and Daman and Diu',
  '27':'Maharashtra','29':'Karnataka','30':'Goa','31':'Lakshadweep','32':'Kerala','33':'Tamil Nadu','34':'Puducherry',
  '35':'Andaman and Nicobar Islands','36':'Telangana','37':'Andhra Pradesh','38':'Ladakh',
}
export const unionWithoutLegislature=new Set(['04','26','31','35','38'])
export type TaxProfile={company:string;country:string;region:string;city:string;postal:string;address:string;taxId:string}
export type TaxEstimate={base:number;net:number;total:number;currency:string;behavior:'inclusive'|'exclusive';
  mode:'gst'|'automatic';lines:{label:string;amount:number}[];rates?:string[]}
export const emptyTaxProfile:TaxProfile={company:'',country:'IN',region:'',city:'',postal:'',address:'',taxId:''}

export function validGstin(value:string,region:string) {
  if (!/^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[A-Z0-9]$/.test(value) || value.slice(0,2)!==region) return false
  const alphabet='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  let sum=0
  for (let position=0;position<14;position++) {
    const product=alphabet.indexOf(value[position])*(position%2===0?1:2)
    sum+=Math.floor(product/36)+product%36
  }
  return alphabet[(36-sum%36)%36]===value[14]
}
