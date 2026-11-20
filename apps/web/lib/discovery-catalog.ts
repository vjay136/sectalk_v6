import occupations from './occupations.json'

export const lifeStages = {
  student:'Adult student or independent learner',
  college:'College or university student',
  professional:'Working professional',
  freelancer:'Freelancer or self-employed',
  founder:'Entrepreneur or business owner',
  career_change:'Exploring a career change',
  retired:'Retired',
  other:'Other',
}

const fields = [
  'Accounting','Agriculture','Anthropology','Architecture','Art history','Astronomy','Biology','Biotechnology',
  'Business administration','Chemical engineering','Chemistry','Civil engineering','Computer science','Cybersecurity',
  'Data science','Dentistry','Economics','Education','Electrical engineering','Environmental science','Finance',
  'Graphic design','History','Hospitality','Information technology','Journalism','Law','Library science','Linguistics',
  'Literature','Mathematics','Mechanical engineering','Medicine','Music','Nursing','Pharmacy','Philosophy','Physics',
  'Political science','Psychology','Public health','Robotics','Social work','Sociology','Statistics',
  'Supply chain management','Theatre and film','Urban planning','Veterinary science','Web development',
]
const interests = [
  'Animal care','Animation','Baking','Birdwatching','Board games','Book clubs','Camping','Chess','Cinema','Coding',
  'Community volunteering','Cooking','Crafts','Creative writing','Cricket','Cycling','Dance','Digital art','Drawing',
  'Esports','Fashion','Fitness','Gardening','Hiking','Instrument making','Language exchange','Meditation',
  'Open source','Painting','Photography','Podcasting','Poetry','Public speaking','Reading','Science communication',
  'Singing','Sports','Swimming','Travel','Video production','Woodworking','Yoga',
]
const options = (prefix:string,names:string[]) => names.map(name=>({
  id:prefix+'-'+name.toLowerCase().replace(/[^a-z0-9]+/g,'-'),name,
}))
export const topicGroups = {
  study: options('study',fields),
  interest:options('interest',interests),
  work:occupations,
}
export const topicLabels = Object.fromEntries(Object.values(topicGroups).flat().map(topic=>[topic.id,topic.name]))
